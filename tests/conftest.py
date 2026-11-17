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
    from src.db.audit import init_audit_table, verify_audit_chain, get_connection
    init_db()
    init_audit_table()
    
    # If a previous run or workbench tamper experiment left audit_logs corrupt, reset it
    chain_check = verify_audit_chain()
    if not chain_check["ok"]:
        with get_connection() as conn:
            conn.execute("DELETE FROM audit_logs")
    yield


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
