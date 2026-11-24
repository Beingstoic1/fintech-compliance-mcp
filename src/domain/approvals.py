"""Pure Four-Eyes approval state machine (T07). No I/O.

Lifecycle:
    PENDING --approve (human officer, step-up auth, != requester)--> APPROVED
    APPROVED --execute (officer in tenant, != requester)----------> CONSUMED
    PENDING|APPROVED --reject------------------------------------> REJECTED
    PENDING|APPROVED --TTL elapsed-------------------------------> EXPIRED
CONSUMED / REJECTED / EXPIRED are terminal. The same graph is enforced again by
SQLite triggers in ``src.db.approvals`` (defense in depth).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

APPROVAL_TTL = timedelta(minutes=15)

PENDING, APPROVED, CONSUMED, REJECTED, EXPIRED = "PENDING", "APPROVED", "CONSUMED", "REJECTED", "EXPIRED"
STATUSES: frozenset[str] = frozenset({PENDING, APPROVED, CONSUMED, REJECTED, EXPIRED})
TERMINAL: frozenset[str] = frozenset({CONSUMED, REJECTED, EXPIRED})

TRANSITIONS: dict[str, frozenset[str]] = {
    PENDING: frozenset({APPROVED, REJECTED, EXPIRED}),
    APPROVED: frozenset({CONSUMED, REJECTED, EXPIRED}),
    CONSUMED: frozenset(),
    REJECTED: frozenset(),
    EXPIRED: frozenset(),
}

# Only these staged tools may be executed via an approval. Anything else fails closed.
EXECUTABLE_ACTIONS: frozenset[str] = frozenset({"request_account_freeze", "request_fee_refund"})

# Authentication-method references (RFC 8176) that count as step-up for a sign-off.
STEP_UP_AMR: frozenset[str] = frozenset({"mfa", "hwk", "otp", "swk", "fido"})

OFFICER = "compliance_officer"


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_iso(ts: datetime) -> str:
    """Fixed-width UTC ISO-8601 so lexical comparison in SQL equals time order."""
    return ts.astimezone(UTC).isoformat(timespec="microseconds")


def can_transition(src: str, dst: str) -> bool:
    return dst in TRANSITIONS.get(src, frozenset())


def tenant_matches(approval_tenant: str | None, principal_tenant: str) -> bool:
    """Fail closed: a missing/NULL approval tenant never matches."""
    return bool(approval_tenant) and approval_tenant == principal_tenant


def is_expired(expires_at_iso: str, now: datetime) -> bool:
    return datetime.fromisoformat(expires_at_iso) <= now


@dataclass(frozen=True)
class Verdict:
    ok: bool
    code: str = "OK"
    message: str = ""
    replay: bool = False

    @staticmethod
    def deny(code: str, message: str) -> Verdict:
        return Verdict(False, code, f"{code}: {message}")


ALLOW = Verdict(True)


def _status_denial(status: str) -> Verdict:
    if status == EXPIRED:
        return Verdict.deny("EXPIRED", "approval has passed its 15-minute TTL")
    return Verdict.deny(f"ALREADY_{status}", "approval cannot be used")


def check_approve(approval: Mapping[str, Any], *, sub: str, role: str, tenant_id: str,
                  amr: Iterable[str], now: datetime) -> Verdict:
    """Rules for a human officer's sign-off."""
    if role != OFFICER:
        return Verdict.deny("RBAC_BLOCK", "only a compliance_officer may approve")
    if not (set(amr) & STEP_UP_AMR):
        return Verdict.deny("STEP_UP_REQUIRED", "approval requires step-up authentication")
    if not tenant_matches(approval.get("tenant_id"), tenant_id):
        return Verdict.deny("TENANT_ISOLATION_VIOLATION", "approval belongs to a different tenant")
    if approval["status"] != PENDING:
        return _status_denial(approval["status"])
    if is_expired(approval["expires_at"], now):
        return Verdict.deny("EXPIRED", "approval has passed its 15-minute TTL")
    if approval["requester_sub"] == sub:
        return Verdict.deny("DUAL_CONTROL_VIOLATION", "compliance_officer cannot approve their own request")
    if approval["tool_name"] not in EXECUTABLE_ACTIONS:
        return Verdict.deny("UNKNOWN_ACTION", "approval references a non-executable tool")
    return ALLOW


def check_execute(approval: Mapping[str, Any], *, sub: str, role: str, tenant_id: str,
                  now: datetime, idempotency_key: str | None = None) -> Verdict:
    """Rules for executing an approved action (the executor may be the approver)."""
    if role != OFFICER:
        return Verdict.deny("RBAC_BLOCK", "only a compliance_officer may execute")
    if not tenant_matches(approval.get("tenant_id"), tenant_id):
        return Verdict.deny("TENANT_ISOLATION_VIOLATION", "approval belongs to a different tenant")
    status = approval["status"]
    if status == CONSUMED and idempotency_key and \
            approval.get("execution_idempotency_key") == idempotency_key:
        return Verdict(True, "REPLAY", replay=True)
    if status == PENDING:
        return Verdict.deny("NOT_APPROVED", "approval requires a human compliance-officer sign-off first")
    if status != APPROVED:
        return _status_denial(status)
    if is_expired(approval["expires_at"], now):
        return Verdict.deny("EXPIRED", "approval has passed its 15-minute TTL")
    if approval["requester_sub"] == sub:
        return Verdict.deny("DUAL_CONTROL_VIOLATION", "compliance_officer cannot execute their own request")
    if approval["tool_name"] not in EXECUTABLE_ACTIONS:
        return Verdict.deny("UNKNOWN_ACTION", "approval references a non-executable tool")
    return ALLOW


def check_reject(approval: Mapping[str, Any], *, role: str, tenant_id: str) -> Verdict:
    if role != OFFICER:
        return Verdict.deny("RBAC_BLOCK", "only a compliance_officer may reject")
    if not tenant_matches(approval.get("tenant_id"), tenant_id):
        return Verdict.deny("TENANT_ISOLATION_VIOLATION", "approval belongs to a different tenant")
    if approval["status"] not in (PENDING, APPROVED):
        return _status_denial(approval["status"])
    return ALLOW
