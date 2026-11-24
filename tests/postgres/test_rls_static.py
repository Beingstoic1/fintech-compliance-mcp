"""T10 guards that run without Postgres: schema drift checks on the RLS SQL, the
tenant session helper's contract, and mandatory tenant scoping in the SQLite DAL."""
from __future__ import annotations

import inspect
import re
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from src.db.postgres import SCHEMA_SQL
from src.db.postgres.session import SET_TENANT_SQL, tenant_transaction

SQL = SCHEMA_SQL.read_text()
TABLES = re.findall(r"CREATE TABLE fintech\.(\w+)\s*\((.*?)\n\);", SQL, flags=re.S)


def test_every_table_has_enabled_and_forced_rls_and_a_policy():
    assert {t for t, _ in TABLES} >= {"tenants", "accounts", "transactions", "kyc_records",
                                      "compliance_alerts", "pending_approvals", "audit_logs",
                                      "audit_meta"}
    for table, _ in TABLES:
        assert re.search(rf"ALTER TABLE fintech\.{table}\s+ENABLE\s+ROW LEVEL SECURITY", SQL), table
        assert re.search(rf"ALTER TABLE fintech\.{table}\s+FORCE\s+ROW LEVEL SECURITY", SQL), table
        assert re.search(rf"CREATE POLICY \w+ ON fintech\.{table}\b", SQL), table


def test_every_tenant_table_is_scoped_by_current_tenant_for_the_app_role():
    for table, body in TABLES:
        if not re.search(r"^\s*tenant_id\s", body, flags=re.M):
            continue
        policies = re.findall(rf"CREATE POLICY \w+ ON fintech\.{table}\b(.*?);", SQL, flags=re.S)
        app = [p for p in policies if "TO fintech_app" in p]
        assert app, table
        assert all("tenant_id = fintech.current_tenant()" in p for p in app), table
        assert not any("USING (true)" in p for p in app), table


def test_audit_ledger_is_insert_select_only_for_the_app():
    grants = re.findall(r"GRANT ([^;]*?)\s+ON fintech\.audit_logs\s+TO fintech_app", SQL)
    assert grants == ["SELECT, INSERT"]
    assert "audit_meta        TO fintech_app" not in SQL
    for trig in ("audit_logs_no_mutation", "audit_logs_no_truncate", "audit_logs_link_guard"):
        assert f"CREATE TRIGGER {trig}" in SQL


def test_no_role_bypasses_rls_and_public_gets_nothing():
    assert re.findall(r"(?<!NO)BYPASSRLS", SQL) == []
    assert not re.search(r"GRANT [^;]* TO [^;]*\bPUBLIC\b", SQL)
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA fintech FROM PUBLIC" in SQL
    assert "SET LOCAL ROLE fintech_owner" in SQL  # objects owned by a non-app role


def test_cross_tenant_references_are_structurally_impossible():
    assert "FOREIGN KEY (refund_of_txn_id, tenant_id) REFERENCES fintech.transactions (txn_id, tenant_id)" in SQL
    assert "FOREIGN KEY (account_id, tenant_id) REFERENCES fintech.accounts (account_id, tenant_id)" in SQL


# ─── session helper ──────────────────────────────────────────────────────────

class _FakeConn:
    def __init__(self, status: str = "IDLE"):
        self.info = SimpleNamespace(transaction_status=SimpleNamespace(name=status))
        self.calls: list = []

    @contextmanager
    def transaction(self):
        self.calls.append("BEGIN")
        yield
        self.calls.append("COMMIT")

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


def test_tenant_transaction_sets_a_transaction_local_tenant():
    conn = _FakeConn()
    with tenant_transaction(conn, "tenant_neobank_in"):
        conn.execute("SELECT 1")
    assert conn.calls == ["BEGIN", (SET_TENANT_SQL, ("tenant_neobank_in",)), ("SELECT 1", None), "COMMIT"]
    assert SET_TENANT_SQL.endswith("true)")  # is_local => SET LOCAL semantics


@pytest.mark.parametrize("bad", ["", "x", "Tenant-A", "t'; RESET ROLE; --", None, 7])
def test_tenant_transaction_rejects_malformed_tenant(bad):
    with pytest.raises(ValueError):
        with tenant_transaction(_FakeConn(), bad):
            pass


def test_tenant_transaction_refuses_to_nest():
    with pytest.raises(RuntimeError):
        with tenant_transaction(_FakeConn(status="INTRANS"), "tenant_neobank_in"):
            pass


# ─── SQLite parity: tenant scope is mandatory ────────────────────────────────

def test_sqlite_dal_requires_tenant_everywhere():
    from src.db import approvals, database

    funcs = [database.get_account, database.get_transactions, database.get_transaction,
             database.get_refunded_total, database.freeze_account, database.refund_transaction,
             database.detect_structuring, approvals.get, approvals.find_by_idempotency,
             approvals.list_for_tenant, approvals.transition, approvals.expire_stale]
    for fn in funcs:
        param = inspect.signature(fn).parameters.get("tenant_id")
        assert param is not None and param.default is inspect.Parameter.empty, fn.__qualname__

    for call in (lambda: database.get_account("ACC-001", ""),
                 lambda: database.get_transactions("ACC-001", tenant_id=""),
                 lambda: database.get_transaction("TXN-N001", "")):
        with pytest.raises(ValueError):
            call()
