"""Pytest configuration and shared fixtures."""
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass

import pytest

# T01: point the app at a throwaway DB BEFORE any `src.db` import (modules init the
# DB at import time). Unconditional: tests must never touch data/fintech_ledger.db.
_TEST_DB_DIR = tempfile.mkdtemp(prefix="fintech_test_db_")
os.environ["FINTECH_DB_PATH"] = os.path.join(_TEST_DB_DIR, "fintech_ledger.db")

# Ensure src/ is on PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session", autouse=True)
def init_database():
    """Initialize the test database once per test session."""
    from src.db.database import DB_PATH, DEFAULT_DB_PATH, init_db
    from src.db.audit import init_audit_table
    assert DB_PATH.resolve() != DEFAULT_DB_PATH.resolve(), "tests must not use the real ledger DB"
    assert str(DB_PATH).startswith(_TEST_DB_DIR)
    init_db()
    init_audit_table()
    yield
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)


@pytest.fixture(autouse=True)
def clean_test_isolation():
    """Ensure complete test isolation across all tests.
    
    The audit ledger is append-only (triggers), so it is wiped through the
    privileged tamper-lab reset (rows, sequence, checkpoint file). Also clears
    pending_approvals, account freezes, and refund rows created during tests.
    """
    from src.db.database import get_connection
    from src.demo.tamper_lab import reset_ledger_for_tests

    def _reset() -> None:
        reset_ledger_for_tests()
        with get_connection() as conn:
            conn.execute("DELETE FROM pending_approvals")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='pending_approvals'")
            conn.execute("UPDATE accounts SET is_frozen=0")
            conn.execute("DELETE FROM transactions WHERE txn_id LIKE 'TXN-REF-%'")

    _reset()
    yield
    _reset()


@pytest.fixture
def junior_token():
    """Session token for junior_alice (junior_analyst, tenant_neobank_in)."""
    from src.security.identity import issue_demo_token
    return issue_demo_token("junior_alice")


@pytest.fixture
def senior_token():
    """Session token for senior_carol (senior_investigator, tenant_neobank_in)."""
    from src.security.identity import issue_demo_token
    return issue_demo_token("senior_carol")


@pytest.fixture
def officer_token():
    """Session token for officer_eve (compliance_officer, tenant_neobank_in)."""
    from src.security.identity import issue_demo_token
    return issue_demo_token("officer_eve")


@pytest.fixture
def officer2_token():
    """Session token for officer_frank (compliance_officer, tenant_b2b_cards) — different officer."""
    from src.security.identity import issue_demo_token
    return issue_demo_token("officer_frank")


# ─── Adversarial test pattern (T03) ──────────────────────────────────────────
# Every adversarial test asserts THREE things:
#   1. the tool response (decision / error code),
#   2. the DB side effect (rows that must or must not exist),
#   3. the audit row the attempt produced.
# Use `principal(sub)` for identities, `db_query` for side effects, `audit_rows` for (3).

@dataclass(frozen=True)
class TestPrincipal:
    __test__ = False  # not a test class
    token: str
    sub: str
    role: str
    tenant_id: str


@pytest.fixture
def principal():
    """Factory: principal("senior_dave") -> TestPrincipal holding a freshly minted dev JWT.

    Call tools with `call_as(p.token, tool, ...)` (src.security.identity); identity is
    never a tool argument.
    """
    from src.security.identity import issue_demo_token, verify_jwt

    def _make(sub: str) -> TestPrincipal:
        token = issue_demo_token(sub)
        v = verify_jwt(token)
        return TestPrincipal(token=token, sub=v.sub, role=v.role, tenant_id=v.tenant_id)

    return _make


@pytest.fixture
def db_query():
    """db_query(sql, params=()) -> list[dict] against the isolated test DB."""
    from src.db.database import get_connection

    def _q(sql: str, params: tuple = ()) -> list[dict]:
        conn = get_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    return _q


@pytest.fixture
def audit_rows(db_query):
    """audit_rows(tool_name=None) -> audit rows in event_id order."""
    def _rows(tool_name: str | None = None) -> list[dict]:
        if tool_name is None:
            return db_query("SELECT * FROM audit_logs ORDER BY event_id")
        return db_query("SELECT * FROM audit_logs WHERE tool_name=? ORDER BY event_id", (tool_name,))
    return _rows


@pytest.fixture
def plant_approval():
    """plant_approval(requester, tool, args, expires_at=None) -> approval_id.

    Inserts a PENDING approval row directly, with a valid keyed binding: simulates a
    request that skipped the staging-time checks (attacker with code access, legacy
    row). Use it to prove the *execute* path defends on its own.
    """
    import uuid as _uuid

    def _plant(requester, tool: str, args: dict, *, expires_at: str | None = None) -> str:
        from src.db import approvals as repo
        from src.db.database import get_connection
        from src.domain import approvals as fsm
        from src.security.binding import bind_args
        from src.security.guardrails import canonical_json

        key_id, digest = bind_args(tool, args, requester.sub, requester.tenant_id)
        now, approval_id = fsm.utc_now(), str(_uuid.uuid4())
        conn = get_connection()
        try:
            repo.insert(conn, approval_id=approval_id, tenant_id=requester.tenant_id,
                        requester_sub=requester.sub, requester_role=requester.role,
                        tool_name=tool, canonical_args_json=canonical_json(args),
                        key_id=key_id, args_digest=digest, created_at=fsm.to_iso(now),
                        expires_at=expires_at or fsm.to_iso(now + fsm.APPROVAL_TTL))
            conn.commit()
        finally:
            conn.close()
        return approval_id

    return _plant


@pytest.fixture
def approve_as():
    """approve_as(officer_sub, approval_id) -> service result.

    Human sign-off through the approval-console service using a step-up (amr=mfa)
    token. Agent tokens from `principal()` carry amr=pwd and cannot approve.
    """
    def _approve(sub: str, approval_id: str, now=None) -> dict:
        from src.security.identity import authenticated, issue_demo_token
        from src.services import approvals as four_eyes

        with authenticated(issue_demo_token(sub, amr=("pwd", "mfa"))) as officer:
            return four_eyes.approve(officer, approval_id, now=now)

    return _approve
