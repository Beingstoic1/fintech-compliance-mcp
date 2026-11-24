"""Adversarial T11–T14: identity forgery, identity injection, unbounded reads, refund amounts.

Follows the T03 pattern: identities from `principal()`, the isolated temp DB, and a
three-way assertion per attack: (1) response, (2) DB side effect, (3) audit row.
"""
import asyncio
import contextlib
import hashlib
import json
import time

import jwt as pyjwt
import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from src.db.database import get_transactions
from src.mcp_server import server
from src.mcp_server.schemas import TOOL_INPUTS
from src.security import identity
from src.security.binding import audit_digest
from src.security.identity import AuthenticationError, JWTTokenVerifier, authenticated, call_as
from src.services import approvals as four_eyes

IDENTITY_FIELDS = ("tenant_id", "role", "user_id", "session_token", "sub")


# ─── helpers ─────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _bearer_in_context(token: str):
    """Put a raw (unverified) bearer into the SDK auth context, with claims that *say*
    compliance_officer. Simulates a confused/compromised middleware: the handler must
    re-verify the token itself and never trust the context's claims."""
    at = AccessToken(token=token, client_id="officer_eve", scopes=["compliance_officer"],
                     expires_at=None, resource=identity.AUDIENCE, subject="officer_eve",
                     claims={"role": "compliance_officer", "tenant_id": "tenant_neobank_in"})
    reset = auth_context_var.set(AuthenticatedUser(at))
    try:
        yield
    finally:
        auth_context_var.reset(reset)


def _sdk_call(token: str, tool: str, arguments: dict) -> dict:
    """Call through the MCP SDK (argument parsing + validation) as `token`."""
    async def _go() -> dict:
        with authenticated(token):
            result = await server.mcp.call_tool(tool, arguments)
        return json.loads(result.content[0].text)
    return asyncio.run(_go())


def _claims(**over) -> dict:
    now = int(time.time())
    base = {"iss": identity.ISSUER, "aud": identity.AUDIENCE, "sub": "officer_eve",
            "role": "compliance_officer", "tenant_id": "tenant_neobank_in", "amr": ["pwd"],
            "iat": now, "nbf": now, "exp": now + 300}
    base.update(over)
    return base


def _forged_tokens(junior_token: str) -> dict[str, str]:
    now = int(time.time())
    real_key = identity._SIGNING_KEY
    header, _payload, sig = junior_token.split(".")
    escalated = pyjwt.utils.base64url_encode(json.dumps(_claims(sub="junior_alice")).encode()).decode()
    return {
        "legacy_deterministic": "tok_demo_officer_eve_"
                                + hashlib.sha256(b"demo_session:officer_eve").hexdigest()[:16],
        "unsigned_alg_none": pyjwt.encode(_claims(), None, algorithm="none"),
        "attacker_key": pyjwt.encode(_claims(), "attacker-controlled-key-0123456789abcdef",
                                     algorithm="HS256"),
        "alg_hs512_real_key": pyjwt.encode(_claims(), real_key, algorithm="HS512"),
        "expired": pyjwt.encode(_claims(iat=now - 900, nbf=now - 900, exp=now - 120), real_key,
                                algorithm="HS256"),
        "not_yet_valid": pyjwt.encode(_claims(nbf=now + 600, exp=now + 900), real_key,
                                      algorithm="HS256"),
        "lifetime_over_1h": pyjwt.encode(_claims(exp=now + 7200), real_key, algorithm="HS256"),
        "wrong_audience": pyjwt.encode(_claims(aud="some-other-api"), real_key, algorithm="HS256"),
        "payload_swapped_role": f"{header}.{escalated}.{sig}",
    }


def _approved_freeze(principal, approve_as, account_id="ACC-003") -> str:
    senior = principal("senior_carol")
    staged = call_as(senior.token, server.request_account_freeze, account_id, "adversarial target")
    assert staged["decision"] == "ESCALATE"
    assert approve_as("officer_eve", staged["approval_id"])["decision"] == "APPROVED"
    return staged["approval_id"]


# ─── T11: forged / unsigned / expired bearer tokens ──────────────────────────

def test_t11_forged_and_expired_tokens_rejected_without_logging_token(
        principal, approve_as, db_query, audit_rows, monkeypatch):
    junior = principal("junior_alice")
    approval_id = _approved_freeze(principal, approve_as)
    forged = _forged_tokens(junior.token)
    # HTTP mode never falls back to the operator's stdio token, even if one is set.
    monkeypatch.setenv("FINTECH_STDIO_BEARER_TOKEN", principal("officer_eve").token)
    assert identity._STDIO_MODE is False
    before = len(audit_rows())

    for label, token in forged.items():
        # (1a) HTTP layer: the bearer middleware gets None -> 401
        assert asyncio.run(JWTTokenVerifier().verify_token(token)) is None, label
        # (1b) in-process adapter refuses to bind it
        with pytest.raises(AuthenticationError, match=r"^UNAUTHENTICATED$"):
            call_as(token, server.execute_approved_action, approval_id)
        # (1c) poisoned auth context: handler re-verifies and blocks generically
        with _bearer_in_context(token):
            res = server.execute_approved_action(approval_id)
        assert res == {"error": "UNAUTHENTICATED", "decision": "BLOCK"}, label

    # no bearer at all (HTTP mode) -> same generic block
    assert server.execute_approved_action(approval_id) == {"error": "UNAUTHENTICATED",
                                                           "decision": "BLOCK"}

    # (2) side effect: the APPROVED action was never consumed or performed
    row = db_query("SELECT status, executed_by_sub FROM pending_approvals WHERE approval_id=?",
                   (approval_id,))[0]
    assert (row["status"], row["executed_by_sub"]) == ("APPROVED", None)
    assert db_query("SELECT is_frozen FROM accounts WHERE account_id='ACC-003'")[0]["is_frozen"] == 0

    # (3) audit: one anonymous BLOCK per attempt, and no token material anywhere
    new = audit_rows()[before:]
    assert len(new) == len(forged) + 1
    assert all((r["session_sub"], r["actor_role"], r["tenant_id"], r["decision"]) ==
               ("unknown", "unknown", "unknown", "BLOCK") for r in new)
    assert all(json.loads(r["detail"]) == {"code": "UNAUTHENTICATED"} for r in new)
    secrets_ = {s for t in forged.values() for s in [t, *t.split(".")] if len(s) >= 16}
    secrets_.add(str(identity._SIGNING_KEY))
    for r in audit_rows():
        blob = json.dumps(r)
        assert not any(s in blob for s in secrets_), "token material leaked into the audit row"


# ─── T12: identity fields injected as tool arguments ─────────────────────────

def test_t12_input_models_forbid_identity_extras():
    for tool, model in TOOL_INPUTS.items():
        for field in IDENTITY_FIELDS:
            with pytest.raises(ValidationError) as exc:
                model.model_validate({field: "tenant_b2b_cards"})
            assert any(e["type"] == "extra_forbidden" and e["loc"] == (field,)
                       for e in exc.value.errors()), (tool, field)


def test_t12_advertised_tool_schemas_carry_no_identity_fields():
    tools = asyncio.run(server.mcp.list_tools())
    assert tools
    for t in tools:
        assert not set(IDENTITY_FIELDS) & set(t.input_schema.get("properties", {})), t.name


def test_t12_sdk_injected_identity_is_ignored(principal, db_query, audit_rows):
    junior = principal("junior_alice")  # tenant_neobank_in
    senior = principal("senior_carol")  # tenant_neobank_in
    inject = {"tenant_id": "tenant_b2b_cards", "role": "compliance_officer",
              "user_id": "officer_frank", "session_token": "tok_demo_officer_frank"}

    # Read across tenants: ACC-006 belongs to tenant_b2b_cards
    res = _sdk_call(junior.token, "get_account_profile", {"account_id": "ACC-006", **inject})
    assert res == {"error": "Account not found", "decision": "BLOCK"}
    # Role escalation on an own-tenant read: projection stays junior (masked)
    res = _sdk_call(junior.token, "get_account_profile",
                    {"account_id": "ACC-001", **inject, "tenant_id": "tenant_neobank_in"})
    assert res["decision"] == "REDACT" and res["actor_role"] == "junior_analyst"
    assert res["data"]["account_number"] == "****4821"
    # Write: RBAC uses the JWT role, not the injected one
    res = _sdk_call(junior.token, "request_account_freeze",
                    {"account_id": "ACC-001", "reason": "escalate me", **inject})
    assert res["decision"] == "BLOCK" and res["error"].startswith("RBAC_BLOCK")
    # Write by a permitted role: the approval is stamped with the JWT tenant/sub
    res = _sdk_call(senior.token, "request_account_freeze",
                    {"account_id": "ACC-003", "reason": "injected tenant", **inject})
    assert res["decision"] == "ESCALATE"

    # (2) side effects
    rows = db_query("SELECT tenant_id, requester_sub, canonical_args_json FROM pending_approvals")
    assert len(rows) == 1
    assert (rows[0]["tenant_id"], rows[0]["requester_sub"]) == (senior.tenant_id, senior.sub)
    assert set(json.loads(rows[0]["canonical_args_json"])) == {"account_id", "reason"}

    # (3) audit rows carry the verified identity only
    profile = audit_rows("get_account_profile")
    assert [(r["session_sub"], r["tenant_id"], r["decision"]) for r in profile] == [
        (junior.sub, junior.tenant_id, "BLOCK"), (junior.sub, junior.tenant_id, "REDACT")]
    assert all(r["tenant_id"] != "tenant_b2b_cards" for r in audit_rows())
    freeze = audit_rows("request_account_freeze")
    assert [r["decision"] for r in freeze] == ["BLOCK", "ESCALATE"]
    assert freeze[1]["session_sub"] == senior.sub


# ─── T13: unbounded / malformed `limit` ──────────────────────────────────────

def test_t13_query_limit_rejected_and_never_over_100_rows(principal, insert_txn, audit_rows):
    senior = principal("senior_carol")
    for i in range(150):  # make "more than 100" reachable
        insert_txn(f"TXN-ADV-BULK-{i:03d}", "ACC-002", "tenant_neobank_in", "bulk row",
                   f"2099-01-01 00:{i // 60:02d}:{i % 60:02d}")

    bad = [-1, 0, 101, 10_000, True, "10", 1.5]
    for limit in bad:
        # (1a) handler boundary (in-process callers): BLOCK
        res = call_as(senior.token, server.query_transactions, "ACC-002", limit=limit)
        assert res == {"error": "INVALID_INPUT: limit", "decision": "BLOCK"}, limit
        # (1b) SDK boundary (wire callers): rejected before the handler
        with pytest.raises(ToolError, match="limit"):
            _sdk_call(senior.token, "query_transactions", {"account_id": "ACC-002", "limit": limit})
    # (1c) storage layer refuses on its own (boundary bypassed)
    for limit in (-1, 0, 101, True):
        with pytest.raises(ValueError, match="INVALID_LIMIT"):
            get_transactions("ACC-002", limit=limit, tenant_id="tenant_neobank_in")

    # (2) the cap holds: 150+ rows exist, at most 100 come back
    full = call_as(senior.token, server.query_transactions, "ACC-002", limit=100)
    assert full["decision"] == "ALLOW" and len(full["data"]) == 100
    default = call_as(senior.token, server.query_transactions, "ACC-002")
    assert len(default["data"]) == 50

    # (3) audit: every rejection is a BLOCK with a code, for the real caller. In-process
    # rejections are INVALID_INPUT; wire rejections (refused by the SDK before the handler
    # runs) are SDK_ARGS_REJECTED since T23. No other BLOCK rows exist.
    blocked = [r for r in audit_rows("query_transactions") if r["decision"] == "BLOCK"]
    codes = sorted(json.loads(r["detail"])["code"] for r in blocked)
    assert codes == ["INVALID_INPUT"] * len(bad) + ["SDK_ARGS_REJECTED"] * len(bad)
    assert all(r["session_sub"] == senior.sub and r["tenant_id"] == senior.tenant_id for r in blocked)


# ─── T14: refund amounts (negative, zero, over original, cumulative) ─────────

def _refund_rows(db_query, txn_id: str) -> list[dict]:
    return db_query("SELECT amount_cents FROM transactions WHERE refund_of_txn_id=?", (txn_id,))


def test_t14_refund_amounts_rejected_without_refund_rows(principal, approve_as, debit_txn,
                                                         db_query, audit_rows):
    senior, officer = principal("senior_carol"), principal("officer_eve")
    txn = debit_txn()
    orig, tid = txn["amount_cents"], txn["txn_id"]
    assert orig > 20

    def stage(amount):
        return call_as(senior.token, server.request_fee_refund, tid, amount, "fee refund")

    # (1) boundary: -1 / 0 never reach the domain
    for amount in (-1, 0):
        assert stage(amount) == {"error": "INVALID_INPUT: amount_cents", "decision": "BLOCK"}
    # (1) domain on its own (boundary bypassed by an in-process caller)
    with authenticated(senior.token) as p:
        h = audit_digest("request_fee_refund", {}, p.sub)
        for amount, code in ((-1, "REFUND_AMOUNT_NOT_POSITIVE"), (0, "REFUND_AMOUNT_NOT_POSITIVE"),
                             (True, "INVALID_AMOUNT_TYPE"), (1.5, "INVALID_AMOUNT_TYPE")):
            res = four_eyes.stage_refund(p, {"transaction_id": tid, "amount_cents": amount,
                                             "reason": "bypass"}, h)
            assert res == {"error": code, "decision": "BLOCK"}, amount
    # (1) more than the original
    assert stage(orig + 1) == {"error": "REFUND_EXCEEDS_REFUNDABLE_BALANCE", "decision": "BLOCK"}
    assert db_query("SELECT COUNT(*) AS n FROM pending_approvals")[0]["n"] == 0
    assert _refund_rows(db_query, tid) == []

    # Cumulative: refund all but 10, then 11 more is refused at staging
    first = stage(orig - 10)
    assert approve_as(officer.sub, first["approval_id"])["decision"] == "APPROVED"
    assert call_as(officer.token, server.execute_approved_action,
                   first["approval_id"])["decision"] == "EXECUTED"
    assert stage(11) == {"error": "REFUND_EXCEEDS_REFUNDABLE_BALANCE", "decision": "BLOCK"}

    # Cumulative at execute: two 10s both staged against the same remaining 10
    a, b = stage(10), stage(10)
    for s in (a, b):
        assert approve_as(officer.sub, s["approval_id"])["decision"] == "APPROVED"
    assert call_as(officer.token, server.execute_approved_action, a["approval_id"])["decision"] == "EXECUTED"
    res = call_as(officer.token, server.execute_approved_action, b["approval_id"])
    assert res == {"error": "REFUND_EXCEEDS_REFUNDABLE_BALANCE", "decision": "BLOCK"}

    # Refund of a refund
    refund_id = db_query("SELECT txn_id FROM transactions WHERE refund_of_txn_id=? LIMIT 1", (tid,))[0]["txn_id"]
    assert call_as(senior.token, server.request_fee_refund, refund_id, 1, "refund the refund") == {
        "error": "CANNOT_REFUND_A_REFUND", "decision": "BLOCK"}

    # (2) exactly the original amount refunded, in two rows; the losing approval is not burned
    assert sorted(r["amount_cents"] for r in _refund_rows(db_query, tid)) == sorted([orig - 10, 10])
    assert db_query("SELECT status FROM pending_approvals WHERE approval_id=?",
                    (b["approval_id"],))[0]["status"] == "APPROVED"

    # (3) audit: each refusal is a BLOCK with its rule code; only two EXECUTED rows
    codes = [json.loads(r["detail"])["code"] for r in audit_rows("request_fee_refund")
             if r["decision"] == "BLOCK"]
    assert codes == ["INVALID_INPUT", "INVALID_INPUT", "REFUND_AMOUNT_NOT_POSITIVE",
                     "REFUND_AMOUNT_NOT_POSITIVE", "INVALID_AMOUNT_TYPE", "INVALID_AMOUNT_TYPE",
                     "REFUND_EXCEEDS_REFUNDABLE_BALANCE", "REFUND_EXCEEDS_REFUNDABLE_BALANCE",
                     "CANNOT_REFUND_A_REFUND"]
    exec_rows = audit_rows("execute_approved_action")
    assert [r["decision"] for r in exec_rows] == ["EXECUTED", "EXECUTED", "BLOCK"]
    assert json.loads(exec_rows[-1]["detail"]) == {"code": "REFUND_EXCEEDS_REFUNDABLE_BALANCE"}
