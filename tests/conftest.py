"""Pytest configuration and shared fixtures."""
import os
import sys
import pytest

# Ensure src/ is on PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session", autouse=True)
def init_database():
    """Initialize the test database once per test session."""
    from src.db.database import init_db
    from src.db.audit import init_audit_table
    init_db()
    init_audit_table()
    yield


@pytest.fixture(autouse=True)
def clean_test_isolation():
    """Ensure complete test isolation across all tests.
    
    Wipes audit_logs, pending_approvals, resets sqlite_sequence counters
    so AUTOINCREMENT event_id always starts at 1, resets account freeze status,
    and removes any refund transactions created during testing.
    """
    from src.db.database import get_connection
    with get_connection() as conn:
        conn.execute("DELETE FROM audit_logs")
        conn.execute("DELETE FROM pending_approvals")
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('audit_logs', 'pending_approvals')")
        except Exception:
            pass
        conn.execute("UPDATE accounts SET is_frozen=0")
        conn.execute("DELETE FROM transactions WHERE txn_id LIKE 'TXN-REF-%'")
    yield
    with get_connection() as conn:
        conn.execute("DELETE FROM audit_logs")
        conn.execute("DELETE FROM pending_approvals")
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('audit_logs', 'pending_approvals')")
        except Exception:
            pass
        conn.execute("UPDATE accounts SET is_frozen=0")
        conn.execute("DELETE FROM transactions WHERE txn_id LIKE 'TXN-REF-%'")


@pytest.fixture
def junior_token():
    """Session token for junior_alice (junior_analyst, tenant_neobank_in)."""
    from src.security.session import DEMO_TOKENS
    return DEMO_TOKENS["junior_alice"]


@pytest.fixture
def senior_token():
    """Session token for senior_carol (senior_investigator, tenant_neobank_in)."""
    from src.security.session import DEMO_TOKENS
    return DEMO_TOKENS["senior_carol"]


@pytest.fixture
def officer_token():
    """Session token for officer_eve (compliance_officer, tenant_neobank_in)."""
    from src.security.session import DEMO_TOKENS
    return DEMO_TOKENS["officer_eve"]


@pytest.fixture
def officer2_token():
    """Session token for officer_frank (compliance_officer, tenant_b2b_cards) — different officer."""
    from src.security.session import DEMO_TOKENS
    return DEMO_TOKENS["officer_frank"]
