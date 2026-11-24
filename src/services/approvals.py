"""Four-Eyes application service (T06/T07).

The single implementation of staging, human sign-off, rejection, and execution.
MCP handlers and the Workbench are thin adapters over these functions; rules live
in ``src.domain``, storage in ``src.db``. Every mutation runs in one
``BEGIN IMMEDIATE`` transaction together with its audit row.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Callable

from src.db import approvals as repo
from src.db.audit import log_event, maybe_checkpoint
from src.db.database import (
    freeze_account, get_account, get_connection, get_refunded_total, get_transaction,
    refund_transaction,
)
from src.domain import approvals as fsm
from src.domain.money import Money
from src.domain.refunds import RefundRuleViolation, check_refund, requested_amount
from src.security.binding import audit_digest, bind_args, verify_binding
from src.security.guardrails import canonical_json
from src.security.identity import Principal


# ─── plumbing ────────────────────────────────────────────────────────────────

def _block(p: Principal, tool: str, h: str, code: str, message: str,
           conn: sqlite3.Connection | None = None) -> dict:
    log_event(p.sub, p.role, p.tenant_id, tool, h, "BLOCK", code, conn=conn)
    return {"error": message, "decision": "BLOCK"}


def _write_txn(work: Callable[[sqlite3.Connection], dict]) -> dict:
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        out = work(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    maybe_checkpoint()
    return out


class _Abort(Exception):
    """Roll back the transaction, then return ``response`` (after auditing ``code``)."""

    def __init__(self, code: str, response: dict, decision: str = "BLOCK"):
        super().__init__(code)
        self.code, self.response, self.decision = code, response, decision


def _run(p: Principal, tool: str, h: str, work: Callable[[sqlite3.Connection], dict]) -> dict:
    """Run ``work`` atomically. An ``_Abort`` rolls everything back and is audited
    in its own transaction, so a refused or failed action leaves no partial state."""
    try:
        return _write_txn(work)
    except _Abort as a:
        log_event(p.sub, p.role, p.tenant_id, tool, h, a.decision, a.code)
        return a.response


def _deny(v: fsm.Verdict) -> _Abort:
    return _Abort(v.code, {"error": v.message, "decision": "BLOCK"})


def sweep_expired(tenant_id: str, now: datetime | None = None) -> int:
    """Move overdue PENDING/APPROVED approvals in ``tenant_id`` to EXPIRED."""
    now_iso = fsm.to_iso(now or fsm.utc_now())

    def work(conn: sqlite3.Connection) -> dict:
        n = repo.expire_stale(conn, tenant_id, now_iso)
        if n:
            log_event("system", "system", tenant_id, "expire_sweeper",
                      audit_digest("expire_sweeper", {"tenant_id": tenant_id}, "system"),
                      "EXPIRED", {"code": "APPROVALS_EXPIRED", "count": n}, conn=conn)
        return {"expired": n}

    return _write_txn(work)["expired"]


def list_open(tenant_id: str) -> list[dict]:
    conn = get_connection()
    try:
        return repo.list_for_tenant(conn, tenant_id)
    finally:
        conn.close()


def _escalation(row: dict, replayed: bool = False) -> dict:
    out = {
        "approval_id": row["approval_id"],
        "expires_in_seconds": int(fsm.APPROVAL_TTL.total_seconds()),
        "status": row["status"],
        "decision": "ESCALATE",
        "message": "Approval request created. A compliance_officer must sign off (step-up auth) "
                   "before execution.",
    }
    if replayed:
        out["replayed"] = True
    return out


# ─── staging ─────────────────────────────────────────────────────────────────

def _stage(p: Principal, tool: str, args: dict, h: str, idempotency_key: str | None,
           now: datetime) -> dict:
    key_id, digest = bind_args(tool, args, p.sub, p.tenant_id)

    def work(conn: sqlite3.Connection) -> dict:
        if idempotency_key:
            existing = repo.find_by_idempotency(conn, p.tenant_id, p.sub, idempotency_key)
            if existing is not None:
                same = existing["tool_name"] == tool and verify_binding(
                    existing["key_id"], existing["args_digest"], tool, args, p.sub, p.tenant_id)
                if not same:
                    raise _Abort("IDEMPOTENCY_KEY_REUSED", {
                        "error": "IDEMPOTENCY_KEY_REUSED: key already used for a different request",
                        "decision": "BLOCK"})
                return _escalation(existing, replayed=True)

        approval_id = str(uuid.uuid4())
        repo.insert(conn, approval_id=approval_id, tenant_id=p.tenant_id, requester_sub=p.sub,
                    requester_role=p.role, tool_name=tool, canonical_args_json=canonical_json(args),
                    key_id=key_id, args_digest=digest, created_at=fsm.to_iso(now),
                    expires_at=fsm.to_iso(now + fsm.APPROVAL_TTL), idempotency_key=idempotency_key)
        log_event(p.sub, p.role, p.tenant_id, tool, h, "ESCALATE",
                  {"code": "APPROVAL_CREATED", "approval_id": approval_id}, conn=conn)
        return _escalation(repo.get(conn, approval_id, p.tenant_id))

    return _run(p, tool, h, work)


def stage_freeze(p: Principal, args: dict, h: str, idempotency_key: str | None = None,
                 now: datetime | None = None) -> dict:
    tool = "request_account_freeze"
    if not get_account(args["account_id"], p.tenant_id):
        return _block(p, tool, h, "NOT_FOUND", "Account not found in your tenant scope")
    return _stage(p, tool, args, h, idempotency_key, now or fsm.utc_now())


def stage_refund(p: Principal, args: dict, h: str, idempotency_key: str | None = None,
                 now: datetime | None = None) -> dict:
    tool = "request_fee_refund"
    # Tenant-scoped: another tenant's transaction is indistinguishable from a missing one.
    txn = get_transaction(args["transaction_id"], p.tenant_id)
    if not txn:
        return _block(p, tool, h, "NOT_FOUND", "Transaction not found in your tenant scope")
    currency = txn["currency"]
    try:
        check_refund(
            requested_amount(args["amount_cents"], currency),
            original=Money.from_minor(txn["amount_cents"], currency),
            already_refunded=Money.from_minor(
                get_refunded_total(args["transaction_id"], p.tenant_id), currency),
            original_txn_type=txn["txn_type"],
        )
    except RefundRuleViolation as e:
        return _block(p, tool, h, e.code, e.code)
    return _stage(p, tool, args, h, idempotency_key, now or fsm.utc_now())


# ─── human sign-off / rejection ──────────────────────────────────────────────

def _bound_args(row: dict) -> dict:
    args = json.loads(row["canonical_args_json"])
    if not verify_binding(row["key_id"], row["args_digest"], row["tool_name"], args,
                          row["requester_sub"], row["tenant_id"]):
        raise _Abort("ARGUMENT_BINDING_INVALID", {
            "error": "ARGUMENT_BINDING_INVALID: approval binding does not verify",
            "decision": "BLOCK"})
    return args


def approve(p: Principal, approval_id: str, now: datetime | None = None) -> dict:
    """Human compliance-officer sign-off. Not exposed as an MCP tool: it requires a
    step-up-authenticated principal (``amr``) from the approval console."""
    tool, now = "approve_action", now or fsm.utc_now()
    h = audit_digest(tool, {"approval_id": approval_id}, p.sub)
    sweep_expired(p.tenant_id, now)

    def work(conn: sqlite3.Connection) -> dict:
        row = repo.get(conn, approval_id, p.tenant_id)
        if row is None:
            raise _Abort("NOT_FOUND", {"error": "Approval not found", "decision": "BLOCK"})
        v = fsm.check_approve(row, sub=p.sub, role=p.role, tenant_id=p.tenant_id, amr=p.amr, now=now)
        if not v.ok:
            raise _deny(v)
        _bound_args(row)
        now_iso = fsm.to_iso(now)
        if not repo.transition(conn, approval_id, p.tenant_id, (fsm.PENDING,), fsm.APPROVED,
                               unexpired_at=now_iso, approver_sub=p.sub, approved_at=now_iso,
                               approved_amr=json.dumps(sorted(p.amr))):
            raise _Abort("ALREADY_DECIDED", {"error": "ALREADY_DECIDED: approval state changed",
                                             "decision": "BLOCK"})
        log_event(p.sub, p.role, p.tenant_id, tool, h, "APPROVED",
                  {"code": "APPROVED", "approval_id": approval_id}, conn=conn)
        return {"decision": "APPROVED", "approval_id": approval_id, "approved_by": p.sub}

    return _run(p, tool, h, work)


def reject(p: Principal, approval_id: str, reason: str, h: str,
           now: datetime | None = None) -> dict:
    tool, now = "reject_approved_action", now or fsm.utc_now()

    def work(conn: sqlite3.Connection) -> dict:
        row = repo.get(conn, approval_id, p.tenant_id)
        if row is None:
            raise _Abort("NOT_FOUND", {"error": "Approval not found", "decision": "BLOCK"})
        v = fsm.check_reject(row, role=p.role, tenant_id=p.tenant_id)
        if not v.ok:
            raise _deny(v)
        now_iso = fsm.to_iso(now)
        if not repo.transition(conn, approval_id, p.tenant_id, (fsm.PENDING, fsm.APPROVED),
                               fsm.REJECTED, rejected_by_sub=p.sub, rejected_at=now_iso,
                               rejection_reason=reason):
            raise _Abort("ALREADY_DECIDED", {"error": "ALREADY_DECIDED: approval state changed",
                                             "decision": "BLOCK"})
        log_event(p.sub, p.role, p.tenant_id, tool, h, "REJECTED",
                  {"code": "REJECTED", "approval_id": approval_id}, conn=conn)
        return {"decision": "REJECTED", "approval_id": approval_id, "rejected_by": p.sub}

    return _run(p, tool, h, work)


# ─── execution ───────────────────────────────────────────────────────────────

def _perform(conn: sqlite3.Connection, row: dict, args: dict) -> dict[str, Any]:
    if row["tool_name"] == "request_account_freeze":
        freeze_account(args["account_id"], row["tenant_id"], conn=conn)
        return {"result": "Account frozen successfully", "account_id": args["account_id"]}
    new_txn_id = refund_transaction(args["transaction_id"], args["amount_cents"],
                                    row["tenant_id"], conn=conn)
    return {"result": "Refund processed successfully", "new_txn_id": new_txn_id,
            "amount_cents": args["amount_cents"]}


def execute(p: Principal, approval_id: str, h: str, idempotency_key: str | None = None,
            now: datetime | None = None) -> dict:
    """Consume an APPROVED approval and perform its action, atomically with the audit row.

    A failed action rolls back the consume too: the approval is not burned.
    A retry carrying the same ``idempotency_key`` gets the stored result back.
    """
    tool, now = "execute_approved_action", now or fsm.utc_now()
    sweep_expired(p.tenant_id, now)

    def work(conn: sqlite3.Connection) -> dict:
        row = repo.get(conn, approval_id, p.tenant_id)
        if row is None:
            raise _Abort("NOT_FOUND", {"error": "Approval not found", "decision": "BLOCK"})
        v = fsm.check_execute(row, sub=p.sub, role=p.role, tenant_id=p.tenant_id, now=now,
                              idempotency_key=idempotency_key)
        if not v.ok:
            raise _deny(v)
        if v.replay:
            log_event(p.sub, p.role, p.tenant_id, tool, h, "ALLOW",
                      {"code": "IDEMPOTENT_REPLAY", "approval_id": approval_id}, conn=conn)
            return {**json.loads(row["execution_result_json"]), "replayed": True}

        args = _bound_args(row)
        try:
            action_result = _perform(conn, row, args)
        except RefundRuleViolation as e:
            raise _Abort(e.code, {"error": e.code, "decision": "BLOCK"})
        except Exception:
            raise _Abort("ACTION_EXECUTION_FAILED", {
                "error": "ACTION_EXECUTION_FAILED: internal error during action execution",
                "decision": "BLOCK"}, decision="ERROR")

        result = {"decision": "EXECUTED", "approval_id": approval_id, "action": row["tool_name"],
                  "approved_by": row["approver_sub"], "executed_by": p.sub,
                  "original_requester": row["requester_sub"], **action_result}
        now_iso = fsm.to_iso(now)
        if not repo.transition(conn, approval_id, p.tenant_id, (fsm.APPROVED,), fsm.CONSUMED,
                               unexpired_at=now_iso, executed_by_sub=p.sub, consumed_at=now_iso,
                               execution_idempotency_key=idempotency_key,
                               execution_result_json=json.dumps(result, sort_keys=True)):
            raise _Abort("ALREADY_CONSUMED", {
                "error": "ALREADY_CONSUMED: approval was consumed by a concurrent request",
                "decision": "BLOCK"})
        detail = {"code": "EXECUTED", "approval_id": approval_id, "action": row["tool_name"]}
        if "new_txn_id" in action_result:
            detail["new_txn_id"] = action_result["new_txn_id"]
        log_event(p.sub, p.role, p.tenant_id, tool, h, "EXECUTED", detail, conn=conn)
        return result

    return _run(p, tool, h, work)
