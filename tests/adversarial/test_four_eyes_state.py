"""Adversarial T15–T17, T22: approval tenancy, expiry races, resurrection, idempotency.

Follows the T03 pattern: identities from `principal()`, the isolated temp DB, and a
three-way assertion per attack: (1) response, (2) DB side effect, (3) audit row.
Approvals are planted with `plant_approval` and signed off with `approve_as`.
"""
import json
import sqlite3
import threading
import uuid
from datetime import timedelta

import pytest

from src.db import approvals as repo
from src.db.database import get_connection
from src.domain import approvals as fsm
from src.mcp_server import server
from src.security.binding import audit_digest
from src.security.identity import authenticated, call_as
from src.services import approvals as four_eyes

FREEZE = "request_account_freeze"


def _freeze_args(account_id: str = "ACC-003") -> dict:
    return {"account_id": account_id, "reason": "adversarial four-eyes test"}


def _status(db_query, approval_id: str) -> str:
    return db_query("SELECT status FROM pending_approvals WHERE approval_id=?",
                    (approval_id,))[0]["status"]


def _frozen(db_query, account_id: str = "ACC-003") -> int:
    return db_query("SELECT is_frozen FROM accounts WHERE account_id=?", (account_id,))[0]["is_frozen"]


def _raw(sql: str, params: tuple = ()) -> None:
    conn = get_connection()
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


# ─── T15: NULL-tenant / other-tenant approvals cannot be executed ────────────

def test_t15_other_tenant_approval_is_not_found(principal, plant_approval, approve_as,
                                                db_query, audit_rows):
    victim = principal("senior_carol")        # tenant_neobank_in
    attacker = principal("officer_frank")     # tenant_b2b_cards
    approval_id = plant_approval(victim, FREEZE, _freeze_args())
    assert approve_as("officer_eve", approval_id)["decision"] == "APPROVED"
    not_found = {"error": "Approval not found", "decision": "BLOCK"}

    # (1) execute / reject / approve from the other tenant all read as NOT_FOUND,
    #     byte-identical to a random id (existence is not disclosed)
    assert call_as(attacker.token, server.execute_approved_action, approval_id) == not_found
    assert call_as(attacker.token, server.execute_approved_action, str(uuid.uuid4())) == not_found
    assert call_as(attacker.token, server.reject_approved_action, approval_id, "cross-tenant") == not_found
    assert approve_as(attacker.sub, approval_id) == not_found

    # (2) nothing moved in the victim tenant
    row = db_query("SELECT status, approver_sub, rejected_by_sub FROM pending_approvals "
                   "WHERE approval_id=?", (approval_id,))[0]
    assert (row["status"], row["approver_sub"], row["rejected_by_sub"]) == ("APPROVED", "officer_eve", None)
    assert _frozen(db_query) == 0

    # (3) audit: attacker rows are BLOCK/NOT_FOUND in the attacker's tenant, no victim id
    rows = [r for r in audit_rows() if r["session_sub"] == attacker.sub]
    assert len(rows) == 4
    assert all(r["tenant_id"] == attacker.tenant_id and r["decision"] == "BLOCK"
               and json.loads(r["detail"]) == {"code": "NOT_FOUND"} for r in rows)
    assert not any(approval_id in json.dumps(r) for r in rows)


def test_t15_null_or_empty_tenant_approval_cannot_exist_or_execute(principal, plant_approval,
                                                                   approve_as, db_query, audit_rows):
    senior, officer = principal("senior_carol"), principal("officer_eve")
    template = db_query("SELECT * FROM pending_approvals WHERE approval_id=?",
                        (plant_approval(senior, FREEZE, _freeze_args()),))[0]

    # (1) SQL layer: a NULL tenant can never be stored
    nulled = {**template, "approval_id": str(uuid.uuid4()), "tenant_id": None}
    cols = ", ".join(nulled)
    with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
        _raw(f"INSERT INTO pending_approvals ({cols}) VALUES ({', '.join('?' * len(nulled))})",
             tuple(nulled.values()))

    # An empty-string tenant (passes NOT NULL) is invisible to every real tenant
    empty_id = str(uuid.uuid4())
    empty = {**template, "approval_id": empty_id, "tenant_id": ""}
    _raw(f"INSERT INTO pending_approvals ({cols}) VALUES ({', '.join('?' * len(empty))})",
         tuple(empty.values()))
    assert call_as(officer.token, server.execute_approved_action, empty_id) == {
        "error": "Approval not found", "decision": "BLOCK"}
    assert approve_as(officer.sub, empty_id)["error"] == "Approval not found"
    conn = get_connection()
    try:
        with pytest.raises(ValueError, match="tenant_id is required"):
            repo.get(conn, empty_id, "")
    finally:
        conn.close()

    # Domain layer fails closed on a missing tenant
    for t in (None, ""):
        row = {**template, "tenant_id": t, "status": fsm.APPROVED}
        v = fsm.check_execute(row, sub=officer.sub, role=officer.role, tenant_id=officer.tenant_id,
                              now=fsm.utc_now())
        assert (v.ok, v.code) == (False, "TENANT_ISOLATION_VIOLATION")

    # (2) nothing executed
    assert _status(db_query, empty_id) == "PENDING" and _frozen(db_query) == 0
    # (3) audit: both attempts BLOCK/NOT_FOUND for the real officer
    blocks = [r for r in audit_rows() if r["session_sub"] == officer.sub]
    assert [json.loads(r["detail"])["code"] for r in blocks] == ["NOT_FOUND", "NOT_FOUND"]
    assert all(r["decision"] == "BLOCK" for r in blocks)


def test_t15_legacy_null_tenant_rows_are_orphaned_and_rejected_on_migration():
    """The pre-T07 table allowed NULL tenants; migration must neutralise them."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE pending_approvals (approval_id TEXT PRIMARY KEY, tenant_id TEXT,
        requester_sub TEXT, requester_role TEXT, tool_name TEXT, canonical_args_json TEXT,
        args_sha256 TEXT, status TEXT, created_at TEXT, expires_at TEXT, approver_sub TEXT,
        consumed_at TEXT)""")
    legacy_id = str(uuid.uuid4())
    conn.execute("INSERT INTO pending_approvals VALUES (?,NULL,'senior_carol','senior_investigator',"
                 "?, '{}', 'deadbeef', 'APPROVED', '2026-01-01', '2099-01-01', 'officer_eve', NULL)",
                 (legacy_id, FREEZE))
    repo.init_schema(conn)

    row = dict(conn.execute("SELECT * FROM pending_approvals").fetchone())
    assert (row["tenant_id"], row["status"], row["key_id"]) == ("__orphaned__", "REJECTED", "legacy-unkeyed")
    assert repo.get(conn, legacy_id, "tenant_neobank_in") is None
    with pytest.raises(sqlite3.IntegrityError, match="ILLEGAL_APPROVAL_TRANSITION"):
        conn.execute("UPDATE pending_approvals SET status='APPROVED' WHERE approval_id=?", (legacy_id,))
    conn.close()


# ─── T16: approval expires between read and consume (frozen clock) ───────────

def test_t16_frozen_clock_expiry_boundary(principal, plant_approval, approve_as, db_query, audit_rows):
    senior, officer = principal("senior_carol"), principal("officer_eve")
    t0 = fsm.utc_now().replace(microsecond=0)
    expires = t0 + timedelta(minutes=10)
    ok_id = plant_approval(senior, FREEZE, _freeze_args("ACC-004"), expires_at=fsm.to_iso(expires))
    late_id = plant_approval(senior, FREEZE, _freeze_args("ACC-003"), expires_at=fsm.to_iso(expires))
    for aid in (ok_id, late_id):
        assert approve_as(officer.sub, aid, now=t0)["decision"] == "APPROVED"

    with authenticated(officer.token) as p:
        h = audit_digest("execute_approved_action", {}, p.sub)
        # (1) one microsecond before expiry executes; exactly at expiry does not
        res_ok = four_eyes.execute(p, ok_id, h, now=expires - timedelta(microseconds=1))
        res_late = four_eyes.execute(p, late_id, h, now=expires)
    assert res_ok["decision"] == "EXECUTED"
    assert res_late["decision"] == "BLOCK" and res_late["error"].startswith("EXPIRED")

    # (2) the sweeper expired the late one; only the in-time freeze happened
    assert (_status(db_query, ok_id), _status(db_query, late_id)) == ("CONSUMED", "EXPIRED")
    assert (_frozen(db_query, "ACC-004"), _frozen(db_query, "ACC-003")) == (1, 0)
    # (3) audit: EXECUTED, then the sweep (EXPIRED, count=1), then BLOCK/EXPIRED
    sweep = audit_rows("expire_sweeper")
    assert len(sweep) == 1 and json.loads(sweep[0]["detail"]) == {"code": "APPROVALS_EXPIRED", "count": 1}
    assert [(r["decision"], json.loads(r["detail"])["code"]) for r in audit_rows("execute_approved_action")] \
        == [("EXECUTED", "EXECUTED"), ("BLOCK", "EXPIRED")]


def test_t16_stale_read_is_refused_by_sql_expiry_predicate(principal, plant_approval, approve_as,
                                                           db_query, audit_rows, monkeypatch):
    """The read saw the approval as live (stale clock, sweeper lagging), but the
    consume CAS carries its own ``expires_at > now`` predicate and refuses it."""
    senior, officer = principal("senior_carol"), principal("officer_eve")
    t0 = fsm.utc_now().replace(microsecond=0)
    expires = t0 + timedelta(minutes=10)
    exec_id = plant_approval(senior, FREEZE, _freeze_args(), expires_at=fsm.to_iso(expires))
    pend_id = plant_approval(senior, FREEZE, _freeze_args("ACC-004"), expires_at=fsm.to_iso(expires))
    assert approve_as(officer.sub, exec_id, now=t0)["decision"] == "APPROVED"

    monkeypatch.setattr(fsm, "is_expired", lambda *_: False)    # domain read: "still live"
    monkeypatch.setattr(repo, "expire_stale", lambda *_: 0)    # sweeper has not run yet
    late = expires + timedelta(seconds=1)
    with authenticated(officer.token) as p:
        res_exec = four_eyes.execute(p, exec_id, audit_digest("x", {}, p.sub), now=late)
    res_appr = approve_as(officer.sub, pend_id, now=late)
    monkeypatch.undo()

    # (1) both refused
    assert res_exec["decision"] == "BLOCK" and res_exec["error"].startswith("STATE_CHANGED_OR_EXPIRED")
    assert res_appr["decision"] == "BLOCK" and res_appr["error"].startswith("STATE_CHANGED_OR_EXPIRED")
    # (2) the in-transaction freeze rolled back with the failed CAS; nothing transitioned
    assert _frozen(db_query) == 0
    assert (_status(db_query, exec_id), _status(db_query, pend_id)) == ("APPROVED", "PENDING")
    assert four_eyes.sweep_expired(senior.tenant_id, late) == 2
    # (3) audit: BLOCK rows, never EXECUTED / a second APPROVED
    assert [r["decision"] for r in audit_rows("execute_approved_action")] == ["BLOCK"]
    assert [r["decision"] for r in audit_rows("approve_action")] == ["APPROVED", "BLOCK"]
    assert json.loads(audit_rows("execute_approved_action")[-1]["detail"]) == {
        "code": "STATE_CHANGED_OR_EXPIRED"}


# ─── T17: status resurrection blocked at the SQL layer ───────────────────────

def test_t17_terminal_status_resurrection_blocked_in_sql(principal, plant_approval, approve_as,
                                                         db_query, audit_rows):
    senior, officer = principal("senior_carol"), principal("officer_eve")
    # Reach each terminal state through the real service paths
    rejected = plant_approval(senior, FREEZE, _freeze_args())
    assert call_as(officer.token, server.reject_approved_action, rejected, "not warranted")["decision"] == "REJECTED"
    expired = plant_approval(senior, FREEZE, _freeze_args(),
                             expires_at=fsm.to_iso(fsm.utc_now() - timedelta(seconds=1)))
    assert four_eyes.sweep_expired(senior.tenant_id) == 1
    consumed = plant_approval(senior, FREEZE, _freeze_args("ACC-004"))
    assert approve_as(officer.sub, consumed)["decision"] == "APPROVED"
    assert call_as(officer.token, server.execute_approved_action, consumed)["decision"] == "EXECUTED"
    terminal = {rejected: "REJECTED", expired: "EXPIRED", consumed: "CONSUMED"}
    snapshot = db_query("SELECT * FROM pending_approvals ORDER BY approval_id")
    audit_before = len(audit_rows())

    attacks = []
    for aid in terminal:
        attacks += [
            ("UPDATE pending_approvals SET status='APPROVED' WHERE approval_id=?", (aid,),
             "ILLEGAL_APPROVAL_TRANSITION"),
            ("UPDATE pending_approvals SET status='PENDING' WHERE approval_id=?", (aid,),
             "ILLEGAL_APPROVAL_TRANSITION"),
            ("UPDATE pending_approvals SET status='APPROVED', approver_sub='officer_eve', "
             "expires_at='2099-01-01T00:00:00.000000+00:00' WHERE approval_id=?", (aid,),
             "ILLEGAL_APPROVAL_TRANSITION|APPROVAL_ROW_IMMUTABLE"),
        ]
    attacks.append(("UPDATE pending_approvals SET status='REJECTED' WHERE approval_id=?", (consumed,),
                    "ILLEGAL_APPROVAL_TRANSITION"))  # rewrite history of an executed action
    # Overwrite / forge: copy the consumed row's still-valid binding into an APPROVED row
    src = {k: v for k, v in db_query("SELECT * FROM pending_approvals WHERE approval_id=?",
                                     (consumed,))[0].items()}
    for forged in ({**src, "status": "APPROVED", "consumed_at": None, "executed_by_sub": None,
                    "execution_result_json": None},                          # REPLACE in place
                   {**src, "approval_id": str(uuid.uuid4()), "status": "APPROVED",
                    "consumed_at": None, "executed_by_sub": None, "execution_result_json": None}):
        cols = ", ".join(forged)
        attacks.append((f"INSERT OR REPLACE INTO pending_approvals ({cols}) "
                        f"VALUES ({', '.join('?' * len(forged))})", tuple(forged.values()),
                        "ILLEGAL_APPROVAL_INSERT"))

    # (1) every raw SQL attempt aborts with the guard's code
    for sql, params, code in attacks:
        with pytest.raises(sqlite3.IntegrityError, match=code):
            _raw(sql, params)
    # ... and so does the repository's own CAS helper
    conn = get_connection()
    try:
        for aid, status in terminal.items():
            with pytest.raises(sqlite3.IntegrityError, match="ILLEGAL_APPROVAL_TRANSITION"):
                repo.transition(conn, aid, senior.tenant_id, (status,), fsm.APPROVED,
                                approver_sub="officer_eve")
    finally:
        conn.close()
    # ... and the service refuses to approve or execute any terminal row
    for aid, status in terminal.items():
        code = "EXPIRED" if status == "EXPIRED" else f"ALREADY_{status}"
        assert approve_as(officer.sub, aid)["error"].startswith(code)
        assert call_as(officer.token, server.execute_approved_action, aid)["error"].startswith(code)

    # (2) the table is byte-identical; ACC-003 was never frozen
    assert db_query("SELECT * FROM pending_approvals ORDER BY approval_id") == snapshot
    assert _frozen(db_query, "ACC-003") == 0
    # (3) audit: only BLOCKs were added (raw SQL attempts leave no partial rows)
    added = audit_rows()[audit_before:]
    assert len(added) == 6 and all(r["decision"] == "BLOCK" for r in added)


# ─── T22: idempotency-key replays ────────────────────────────────────────────

def test_t22_staging_replay_returns_same_approval(principal, db_query, audit_rows):
    senior, other_tenant = principal("senior_carol"), principal("senior_dave")
    key = "idem-key-0001"

    first = call_as(senior.token, server.request_account_freeze, "ACC-003", "replay test", key)
    again = call_as(senior.token, server.request_account_freeze, "ACC-003", "replay test", key)
    clash = call_as(senior.token, server.request_account_freeze, "ACC-004", "replay test", key)
    foreign = call_as(other_tenant.token, server.request_account_freeze, "ACC-007", "replay test", key)

    # (1) same key + args -> same approval; same key + other args -> refused;
    #     the key is namespaced per tenant + requester
    assert first["decision"] == "ESCALATE" and "replayed" not in first
    assert again == {**first, "replayed": True}
    assert clash["decision"] == "BLOCK" and clash["error"].startswith("IDEMPOTENCY_KEY_REUSED")
    assert foreign["decision"] == "ESCALATE" and foreign["approval_id"] != first["approval_id"]
    # (2) exactly one row per (tenant, requester, key)
    rows = db_query("SELECT tenant_id, approval_id FROM pending_approvals WHERE idempotency_key=?", (key,))
    assert sorted((r["tenant_id"], r["approval_id"]) for r in rows) == sorted(
        [(senior.tenant_id, first["approval_id"]), (other_tenant.tenant_id, foreign["approval_id"])])
    # (3) audit: created, replay, reuse-block for carol; created for dave
    carol = [(r["decision"], json.loads(r["detail"])["code"]) for r in audit_rows(FREEZE)
             if r["session_sub"] == senior.sub]
    assert carol == [("ESCALATE", "APPROVAL_CREATED"), ("ALLOW", "IDEMPOTENT_REPLAY"),
                     ("BLOCK", "IDEMPOTENCY_KEY_REUSED")]


def test_t22_concurrent_staging_with_one_key_creates_one_row(principal, db_query, audit_rows):
    senior = principal("senior_carol")
    n, key = 8, "idem-race-0001"
    barrier, results, errors, lock = threading.Barrier(n), [], [], threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=10)
            r = call_as(senior.token, server.request_account_freeze, "ACC-003", "race", key)
            with lock:
                results.append(r)
        except Exception as exc:  # surface thread failures in the main thread
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    # (1) every caller got the same approval_id
    assert len({r["approval_id"] for r in results}) == 1 and len(results) == n
    assert sum("replayed" not in r for r in results) == 1
    # (2) one row
    assert db_query("SELECT COUNT(*) AS n FROM pending_approvals")[0]["n"] == 1
    # (3) one creation audit row, n-1 replays
    codes = [json.loads(r["detail"])["code"] for r in audit_rows(FREEZE)]
    assert codes.count("APPROVAL_CREATED") == 1 and codes.count("IDEMPOTENT_REPLAY") == n - 1


def test_t22_execute_replay_returns_stored_result_without_second_effect(
        principal, approve_as, debit_txn, db_query, audit_rows):
    senior, officer = principal("senior_carol"), principal("officer_eve")
    txn = debit_txn()
    staged = call_as(senior.token, server.request_fee_refund, txn["txn_id"], 100, "dup fee")
    assert approve_as(officer.sub, staged["approval_id"])["decision"] == "APPROVED"
    aid, key = staged["approval_id"], "exec-key-0001"

    first = call_as(officer.token, server.execute_approved_action, aid, key)
    replay = call_as(officer.token, server.execute_approved_action, aid, key)
    other_key = call_as(officer.token, server.execute_approved_action, aid, "exec-key-0002")
    no_key = call_as(officer.token, server.execute_approved_action, aid)

    # (1) same key -> identical stored result; any other attempt is a blocked replay
    assert first["decision"] == "EXECUTED"
    assert replay == {**first, "replayed": True}
    for res in (other_key, no_key):
        assert res["decision"] == "BLOCK" and res["error"].startswith("ALREADY_CONSUMED")
    # (2) one refund row, one CONSUMED transition carrying the key
    refunds = db_query("SELECT txn_id FROM transactions WHERE refund_of_txn_id=?", (txn["txn_id"],))
    assert [r["txn_id"] for r in refunds] == [first["new_txn_id"]]
    row = db_query("SELECT status, execution_idempotency_key FROM pending_approvals "
                   "WHERE approval_id=?", (aid,))[0]
    assert (row["status"], row["execution_idempotency_key"]) == ("CONSUMED", key)
    # (3) audit: EXECUTED once, then the replay, then two BLOCKs
    assert [(r["decision"], json.loads(r["detail"])["code"]) for r in audit_rows("execute_approved_action")] \
        == [("EXECUTED", "EXECUTED"), ("ALLOW", "IDEMPOTENT_REPLAY"),
            ("BLOCK", "ALREADY_CONSUMED"), ("BLOCK", "ALREADY_CONSUMED")]
