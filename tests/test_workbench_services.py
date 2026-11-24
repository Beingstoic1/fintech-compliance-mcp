"""T26: service-level tests for the Workbench tabs.

Each Workbench button is a thin adapter over the calls exercised here (Tab 1:
`call_as(token, <mcp handler>)`; Tab 2: `four_eyes.list_open / approve` plus the
execute/reject handlers; Tab 3: `verify_audit_chain` and the tamper lab). Testing the
calls directly replaces the slow, brittle Streamlit AppTest runs; one AppTest smoke
test (`test_workbench_app_cold_start`) still boots the real app.
"""
import pytest

from src.db.audit import verify_audit_chain
from src.db.database import get_account
from src.demo import tamper_lab
from src.mcp_server import server
from src.security.identity import authenticated, call_as, issue_demo_token
from src.services import approvals as four_eyes


def _officer_console(sub: str = "officer_eve"):
    """The approval console authenticates officers with step-up (amr=mfa)."""
    return authenticated(issue_demo_token(sub, amr=("pwd", "mfa")))


def test_tab1_profile_is_masked_for_junior_and_clear_for_senior():
    junior = call_as(issue_demo_token("junior_alice"), server.get_account_profile, "ACC-001")
    senior = call_as(issue_demo_token("senior_carol"), server.get_account_profile, "ACC-001")
    assert junior["decision"] == "REDACT"
    assert (junior["data"]["account_number"], junior["data"]["tax_id"],
            junior["data"]["holder_name"]) == ("****4821", "XX-XXX4567", "A. S.")
    assert senior["decision"] == "ALLOW"
    assert (senior["data"]["account_number"], senior["data"]["tax_id"]) == ("123456784821", "AB-1234567")


def test_tab1_blocked_tool_surfaces_error_not_exception():
    res = call_as(issue_demo_token("junior_alice"), server.request_account_freeze, "ACC-010", "junior tries")
    assert res["decision"] == "BLOCK" and res["error"].startswith("RBAC_BLOCK")


def test_tab2_queue_approve_then_execute_freezes_account():
    staged = call_as(issue_demo_token("senior_carol"), server.request_account_freeze, "ACC-010",
                     "Suspected sub-threshold smurfing ring activity linked to merchant ACC-015")
    assert staged["decision"] == "ESCALATE"
    queue = four_eyes.list_open("tenant_neobank_in")
    assert [a["approval_id"] for a in queue] == [staged["approval_id"]]
    assert four_eyes.list_open("tenant_b2b_cards") == []  # queue is tenant-scoped

    with _officer_console() as officer:                    # "Approve Only"
        assert four_eyes.approve(officer, staged["approval_id"])["decision"] == "APPROVED"
    res = call_as(issue_demo_token("officer_eve"), server.execute_approved_action,
                  staged["approval_id"])                     # "Execute Action"
    assert res["decision"] == "EXECUTED" and res["action"] == "request_account_freeze"
    assert get_account("ACC-010", "tenant_neobank_in")["is_frozen"] == 1
    assert four_eyes.list_open("tenant_neobank_in") == []


def test_tab2_reject_removes_request_from_queue():
    staged = call_as(issue_demo_token("senior_carol"), server.request_account_freeze, "ACC-010", "reject me")
    res = call_as(issue_demo_token("officer_eve"), server.reject_approved_action,
                  staged["approval_id"], "Rejected in approval console")
    assert res["decision"] == "REJECTED"
    assert four_eyes.list_open("tenant_neobank_in") == []
    assert get_account("ACC-010", "tenant_neobank_in")["is_frozen"] == 0


def test_tab3_verify_tamper_and_restore():
    call_as(issue_demo_token("junior_alice"), server.get_account_profile, "ACC-001")
    assert verify_audit_chain()["ok"] is True                       # "Verify Full Chain"

    tamper_lab.tamper_row(1, "ALLOW")                                # "Simulate Tampering"
    res = verify_audit_chain()
    assert (res["ok"], res["corrupted_event_id"], res["reason"]) == (False, 1, "ENTRY_HMAC_MISMATCH")

    assert tamper_lab.restore_row(1) is True                         # "Restore Chain"
    assert verify_audit_chain()["ok"] is True


def test_tab3_tamper_lab_is_disabled_in_production(monkeypatch):
    monkeypatch.setenv("FINTECH_ENV", "production")
    assert tamper_lab.enabled() is False
    for attack in (lambda: tamper_lab.tamper_row(1, "ALLOW"), lambda: tamper_lab.restore_row(1),
                   lambda: tamper_lab.truncate_tail(1)):
        with pytest.raises(PermissionError):
            attack()
