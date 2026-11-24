"""T10 live RLS tests. Run against a throwaway Postgres database:

    pip install '.[postgres]'
    FINTECH_PG_TEST_DSN=postgresql://postgres@localhost/fintech_test pytest tests/postgres

The DSN must be a superuser (the migration creates roles) and the database name must
contain "test": the fixture drops and recreates the ``fintech`` schema.
"""
from __future__ import annotations

import os
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from src.db.postgres import SCHEMA_SQL  # noqa: E402
from src.db.postgres.session import tenant_transaction  # noqa: E402

DSN = os.environ.get("FINTECH_PG_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="FINTECH_PG_TEST_DSN not set")

errors = psycopg.errors
HASH = "a" * 64


@pytest.fixture
def admin():
    conn = psycopg.connect(DSN, autocommit=True)
    if "test" not in conn.info.dbname:
        conn.close()
        pytest.skip("refusing to run against a database whose name lacks 'test'")
    conn.execute("DROP SCHEMA IF EXISTS fintech CASCADE")
    conn.execute(SCHEMA_SQL.read_text())
    conn.execute("""
        INSERT INTO fintech.tenants (tenant_id, name) VALUES ('t_alpha', 'Alpha'), ('t_beta', 'Beta');
        INSERT INTO fintech.accounts (account_id, tenant_id, holder_name, account_number, account_type)
            VALUES ('ACC-101', 't_alpha', 'A Holder', '111', 'personal'),
                   ('ACC-201', 't_beta',  'B Holder', '222', 'personal');
        INSERT INTO fintech.transactions (txn_id, tenant_id, account_id, amount_cents, currency, txn_type, status)
            VALUES ('TXN-A1', 't_alpha', 'ACC-101', 5000, 'INR', 'debit', 'completed'),
                   ('TXN-B1', 't_beta',  'ACC-201', 7000, 'INR', 'debit', 'completed');
    """)
    yield conn
    conn.close()


def _as(admin_conn, role: str):
    conn = psycopg.connect(DSN, autocommit=True)
    conn.execute(f"SET ROLE {role}")
    return conn


@pytest.fixture
def app(admin):
    conn = _as(admin, "fintech_app")
    yield conn
    conn.close()


def _audit_row(event_id: int, prev: str, tenant: str = "t_alpha") -> tuple:
    return (event_id, "2026-11-24T00:00:00.000000+00:00", "sub", "role", tenant, "tool",
            "digest", "ALLOW", None, "kid", prev, HASH)


_AUDIT_INSERT = """INSERT INTO fintech.audit_logs (event_id, timestamp_utc, session_sub, actor_role,
    tenant_id, tool_name, args_digest, decision, detail, key_id, prev_hash, entry_hash)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""


def test_roles_are_least_privilege(admin):
    rows = admin.execute("""SELECT rolname, rolbypassrls, rolsuper FROM pg_roles
                            WHERE rolname IN ('fintech_owner','fintech_app','fintech_auditor')""").fetchall()
    assert len(rows) == 3 and all(not bypass and not sup for _, bypass, sup in rows)
    rels = admin.execute("""SELECT c.relname, pg_get_userbyid(c.relowner), c.relrowsecurity, c.relforcerowsecurity
                            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                            WHERE n.nspname = 'fintech' AND c.relkind = 'r'""").fetchall()
    assert len(rels) == 8
    assert all(owner == "fintech_owner" and rls and forced for _, owner, rls, forced in rels)


def test_no_tenant_context_sees_nothing(app):
    assert app.execute("SELECT count(*) FROM fintech.accounts").fetchone()[0] == 0
    assert app.execute("SELECT count(*) FROM fintech.transactions").fetchone()[0] == 0


def test_tenant_sees_only_its_rows_and_context_does_not_leak(app):
    with tenant_transaction(app, "t_alpha"):
        ids = [r[0] for r in app.execute("SELECT account_id FROM fintech.accounts").fetchall()]
        other = app.execute("SELECT 1 FROM fintech.transactions WHERE txn_id='TXN-B1'").fetchone()
    assert ids == ["ACC-101"] and other is None
    assert app.execute("SELECT fintech.current_tenant()").fetchone()[0] is None
    assert app.execute("SELECT count(*) FROM fintech.accounts").fetchone()[0] == 0


def test_cross_tenant_writes_are_rejected(app):
    with pytest.raises(errors.InsufficientPrivilege):  # RLS WITH CHECK
        with tenant_transaction(app, "t_alpha"):
            app.execute("""INSERT INTO fintech.transactions
                (txn_id, tenant_id, account_id, amount_cents, currency, txn_type, status)
                VALUES ('TXN-X1', 't_beta', 'ACC-201', 1, 'INR', 'debit', 'completed')""")
    with tenant_transaction(app, "t_alpha"):
        cur = app.execute("UPDATE fintech.accounts SET is_frozen = true WHERE account_id = 'ACC-201'")
        assert cur.rowcount == 0
    with pytest.raises(errors.InsufficientPrivilege):  # column-level grant: only is_frozen
        with tenant_transaction(app, "t_alpha"):
            app.execute("UPDATE fintech.accounts SET holder_name = 'x' WHERE account_id = 'ACC-101'")


def test_cross_tenant_refund_is_a_foreign_key_violation_even_for_superuser(admin):
    with pytest.raises(errors.ForeignKeyViolation):
        admin.execute("""INSERT INTO fintech.transactions
            (txn_id, tenant_id, account_id, amount_cents, currency, txn_type, status, refund_of_txn_id)
            VALUES ('TXN-REF-X', 't_alpha', 'ACC-101', 100, 'INR', 'refund', 'completed', 'TXN-B1')""")


def test_audit_chain_is_linked_append_only_and_tenant_checked(admin, app):
    with tenant_transaction(app, "t_alpha"):
        head = app.execute("SELECT * FROM fintech.audit_lock_head()").fetchone()
        assert head == (0, "GENESIS")
        app.execute(_AUDIT_INSERT, _audit_row(1, "GENESIS"))
    with pytest.raises(errors.IntegrityConstraintViolation, match="AUDIT_CHAIN_LINK_INVALID"):
        with tenant_transaction(app, "t_alpha"):
            app.execute(_AUDIT_INSERT, _audit_row(3, HASH))
    with pytest.raises(errors.InsufficientPrivilege):  # RLS: cannot write another tenant's row
        with tenant_transaction(app, "t_alpha"):
            app.execute(_AUDIT_INSERT, _audit_row(2, HASH, tenant="t_beta"))
    with pytest.raises(errors.InsufficientPrivilege):  # no UPDATE grant
        with tenant_transaction(app, "t_alpha"):
            app.execute("UPDATE fintech.audit_logs SET decision = 'BLOCK'")
    with pytest.raises(errors.InsufficientPrivilege, match="AUDIT_LOG_APPEND_ONLY"):
        admin.execute("UPDATE fintech.audit_logs SET decision = 'BLOCK'")  # superuser: trigger
    owner = _as(admin, "fintech_owner")
    try:
        with pytest.raises(errors.InsufficientPrivilege, match="AUDIT_LOG_APPEND_ONLY"):
            owner.execute("TRUNCATE fintech.audit_logs")
    finally:
        owner.close()

    auditor = _as(admin, "fintech_auditor")
    try:
        assert auditor.execute("SELECT count(*) FROM fintech.audit_logs").fetchone()[0] == 1
        with pytest.raises(errors.InsufficientPrivilege):
            auditor.execute("SELECT * FROM fintech.accounts")
    finally:
        auditor.close()


def test_approval_state_machine_enforced(app):
    approval_id = str(uuid.uuid4())
    with tenant_transaction(app, "t_alpha"):
        app.execute("""INSERT INTO fintech.pending_approvals
            (approval_id, tenant_id, requester_sub, requester_role, tool_name, canonical_args_json,
             key_id, args_digest, created_at, expires_at)
            VALUES (%s, 't_alpha', 'senior', 'senior_investigator', 'request_account_freeze',
                    '{"account_id":"ACC-101"}', 'kid', 'digest', now(), now() + interval '15 minutes')""",
                    (approval_id,))
    with pytest.raises(errors.CheckViolation, match="ILLEGAL_APPROVAL_TRANSITION"):
        with tenant_transaction(app, "t_alpha"):
            app.execute("UPDATE fintech.pending_approvals SET status='CONSUMED', executed_by_sub='o', "
                        "approver_sub='o' WHERE approval_id=%s", (approval_id,))
    with pytest.raises(errors.InsufficientPrivilege):  # args are not in the UPDATE grant
        with tenant_transaction(app, "t_alpha"):
            app.execute("UPDATE fintech.pending_approvals SET canonical_args_json='{}' WHERE approval_id=%s",
                        (approval_id,))
    with tenant_transaction(app, "t_beta"):
        assert app.execute("SELECT 1 FROM fintech.pending_approvals WHERE approval_id=%s",
                           (approval_id,)).fetchone() is None
