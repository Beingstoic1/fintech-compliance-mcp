"""Adversarial tests: reference pattern for T11–T22.

Pattern (follow exactly):
  * identities come from the `principal(sub)` fixture, never hard-coded tokens;
  * the DB is the isolated temp DB from tests/conftest.py (T01);
  * every test asserts (1) response, (2) DB side effect, (3) audit row.
"""
import threading

from src.mcp_server.server import execute_approved_action, request_fee_refund
from src.security.identity import call_as


def _victim_debit(db_query, tenant_id="tenant_neobank_in"):
    rows = db_query(
        "SELECT txn_id, amount_cents FROM transactions "
        "WHERE tenant_id=? AND txn_type='debit' ORDER BY txn_id LIMIT 1",
        (tenant_id,),
    )
    assert rows, "seed data must contain a debit for the victim tenant"
    return rows[0]


def test_cross_tenant_refund_blocked_at_request_and_execute(principal, db_query, audit_rows,
                                                            plant_approval, approve_as):
    attacker = principal("senior_dave")            # tenant_b2b_cards
    attacker_officer = principal("officer_frank")  # tenant_b2b_cards
    victim = _victim_debit(db_query)               # tenant_neobank_in
    assert attacker.tenant_id != "tenant_neobank_in"

    victim_txn_count = lambda: db_query(  # noqa: E731
        "SELECT COUNT(*) AS n FROM transactions WHERE tenant_id='tenant_neobank_in'")[0]["n"]
    before = victim_txn_count()

    # ── Phase 1: request path ────────────────────────────────────────────────
    res = call_as(attacker.token, request_fee_refund, victim["txn_id"], 100, "dup fee")
    # (1) response
    assert res["decision"] == "BLOCK"
    assert "not found in your tenant scope" in res["error"]
    # (2) side effect: no approval was staged
    assert db_query("SELECT COUNT(*) AS n FROM pending_approvals")[0]["n"] == 0
    # (3) audit
    last = audit_rows("request_fee_refund")[-1]
    assert (last["session_sub"], last["tenant_id"], last["decision"]) == (
        attacker.sub, attacker.tenant_id, "BLOCK")

    # ── Phase 2: execute path (approval row planted past the request check, and
    #    signed off by a colluding officer in the attacker's tenant) ─────────────
    args = {"transaction_id": victim["txn_id"], "amount_cents": 100, "reason": "dup fee"}
    approval_id = plant_approval(attacker, "request_fee_refund", args)
    assert approve_as(attacker_officer.sub, approval_id)["decision"] == "APPROVED"
    res = call_as(attacker_officer.token, execute_approved_action, approval_id)
    # (1) response: safe, generic error
    assert res["decision"] == "BLOCK"
    assert res["error"].startswith("ACTION_EXECUTION_FAILED")
    # (2) side effect: zero writes into the victim tenant
    assert victim_txn_count() == before
    assert db_query("SELECT COUNT(*) AS n FROM transactions WHERE refund_of_txn_id=?",
                    (victim["txn_id"],))[0]["n"] == 0
    #     and the consume rolled back with the failed action (approval not burned)
    assert db_query("SELECT status FROM pending_approvals WHERE approval_id=?",
                    (approval_id,))[0]["status"] == "APPROVED"
    # (3) audit: failure recorded, no EXECUTED row
    exec_rows = audit_rows("execute_approved_action")
    assert exec_rows[-1]["decision"] == "ERROR"
    assert all(r["decision"] != "EXECUTED" for r in exec_rows)


def test_concurrent_double_execute_single_effect(principal, db_query, audit_rows, approve_as):
    requester = principal("senior_carol")  # tenant_neobank_in
    officer = principal("officer_eve")     # tenant_neobank_in
    txn = _victim_debit(db_query)

    staged = call_as(requester.token, request_fee_refund, txn["txn_id"], 100, "duplicate fee")
    assert staged["decision"] == "ESCALATE"
    approval_id = staged["approval_id"]
    assert approve_as(officer.sub, approval_id)["decision"] == "APPROVED"

    n_threads = 8
    barrier = threading.Barrier(n_threads)
    results, errors = [], []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=10)
            # contextvars do not cross threads: each worker binds its own credential
            r = call_as(officer.token, execute_approved_action, approval_id)
            with lock:
                results.append(r)
        except Exception as exc:  # surface thread failures in the main thread
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"worker raised: {errors!r}"
    assert len(results) == n_threads

    # (1) response: exactly one winner, every loser blocked as replay/race
    executed = [r for r in results if r["decision"] == "EXECUTED"]
    blocked = [r for r in results if r["decision"] == "BLOCK"]
    assert len(executed) == 1
    assert len(blocked) == n_threads - 1
    assert all(r["error"].startswith("ALREADY_") for r in blocked)

    # (2) side effect: one refund row, approval CONSUMED exactly once
    refunds = db_query("SELECT * FROM transactions WHERE refund_of_txn_id=?", (txn["txn_id"],))
    assert len(refunds) == 1 and refunds[0]["amount_cents"] == 100
    appr = db_query("SELECT status, executed_by_sub FROM pending_approvals WHERE approval_id=?",
                    (approval_id,))[0]
    assert (appr["status"], appr["executed_by_sub"]) == ("CONSUMED", officer.sub)

    # (3) audit: one EXECUTED row, the rest BLOCK
    exec_rows = audit_rows("execute_approved_action")
    assert sum(r["decision"] == "EXECUTED" for r in exec_rows) == 1
    assert sum(r["decision"] == "BLOCK" for r in exec_rows) == n_threads - 1
