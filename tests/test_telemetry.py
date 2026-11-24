"""T23/T24: telemetry recorder, SDK-rejection capture, and the dashboard read model.

Pattern (T03): drive the real handlers, then assert on the response, the
``tool_telemetry`` rows, and the audit rows they must agree with.
"""
import asyncio
import dataclasses
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from src.db import telemetry as store
from src.db.database import get_connection
from src.domain import telemetry as rules
from src.mcp_server import server
from src.security.identity import authenticated, call_as
from src.services import approvals as four_eyes
from src.services import telemetry as ops


def _telemetry_rows(db_query) -> list[dict]:
    return db_query("SELECT * FROM tool_telemetry ORDER BY id")


# ─── pure domain rules ───────────────────────────────────────────────────────

def test_record_shape_has_no_room_for_args_identity_or_tokens():
    assert [f.name for f in dataclasses.fields(rules.ToolCallRecord)] == [
        "tool", "decision", "reason_code", "latency_us"]
    with get_connection() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(tool_telemetry)")]
    assert cols == ["id", "recorded_at", "tool_name", "decision", "reason_code", "latency_us"]


@pytest.mark.parametrize("code", [
    "Account 123456784821 not found", "NOT_FOUND: ACC-001", "eyJhbGciOi", "rbac_block", "A", "X" * 65, 42,
])
def test_non_code_reason_fails_closed(code):
    rec = rules.make_record(tool="get_account_profile", decision="BLOCK", reason_code=code, elapsed_ns=1)
    assert rec.reason_code == rules.INVALID_CODE


def test_make_record_rules():
    rec = rules.make_record(tool="query_transactions", decision="ALLOW", reason_code=None, elapsed_ns=12_345_678)
    assert rec.latency_us == 12_345 and rec.latency_ms == Decimal("12.345")
    unknown = rules.make_record(tool="query_transactions", decision="MAYBE", reason_code="NOT_FOUND", elapsed_ns=0)
    assert (unknown.decision, unknown.reason_code) == ("ERROR", rules.NO_AUDIT_OUTCOME)
    for bad_tool in ("Query", "x", "get-account", "tool; DROP"):
        with pytest.raises(rules.TelemetryError, match="INVALID_TOOL_NAME"):
            rules.make_record(tool=bad_tool, decision="ALLOW", reason_code=None, elapsed_ns=1)
    for bad_ns in (-1, True, 1.5, Decimal(1)):
        with pytest.raises(rules.TelemetryError, match="INVALID_LATENCY"):
            rules.make_record(tool="query_transactions", decision="ALLOW", reason_code=None, elapsed_ns=bad_ns)


def test_percentiles_are_exact_nearest_rank():
    assert rules.nearest_rank([], 50) is None
    assert rules.nearest_rank([7], 95) == 7
    data = list(range(1, 101))  # 1..100
    assert (rules.nearest_rank(data, 50), rules.nearest_rank(data, 95), rules.nearest_rank(data, 100)) == (50, 95, 100)
    assert rules.nearest_rank([4, 1, 3, 2], 50) == 2  # lower median, never interpolated
    for pct in (0, 101, True):
        with pytest.raises(rules.TelemetryError):
            rules.nearest_rank(data, pct)

    recs = [rules.ToolCallRecord("t_a", "ALLOW", None, us) for us in (1000, 3000, 2000)]
    recs += [rules.ToolCallRecord("t_b", "BLOCK", "RBAC_BLOCK", 500),
             rules.ToolCallRecord("t_b", "BLOCK", "NOT_FOUND", 1),
             rules.ToolCallRecord("t_b", "BLOCK", "RBAC_BLOCK", 1),
             rules.ToolCallRecord("t_b", "BLOCK", None, 1)]
    lat = rules.latency_by_tool(recs)
    assert [(s.tool, s.calls, s.p50_ms, s.p95_ms) for s in lat] == [
        ("t_a", 3, Decimal(2), Decimal(3)), ("t_b", 4, Decimal("0.001"), Decimal("0.5"))]
    assert rules.blocked_by_reason(recs) == [("RBAC_BLOCK", 2), ("NOT_FOUND", 1), ("UNSPECIFIED", 1)]


def test_turnaround_and_expiry_rate():
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    pairs = [(t0.isoformat(), (t0 + timedelta(seconds=s)).isoformat()) for s in (30, 60, 90, 600)]
    summary = rules.turnaround_summary(pairs)
    assert summary == rules.TurnaroundSummary(4, Decimal(60), Decimal(600))
    assert rules.turnaround_summary([]) is None
    with pytest.raises(rules.TelemetryError, match="NEGATIVE_TURNAROUND"):
        rules.turnaround_us(pairs[0][1], pairs[0][0])
    with pytest.raises(rules.TelemetryError, match="NAIVE_TIMESTAMP"):
        rules.turnaround_us("2026-01-01T00:00:00", "2026-01-01T00:01:00")

    assert rules.expiry_rate({"CONSUMED": 3, "REJECTED": 0, "EXPIRED": 1, "PENDING": 50}) == Decimal("0.25")
    assert rules.expiry_rate({"PENDING": 2}) is None
    with pytest.raises(rules.TelemetryError):
        rules.expiry_rate({"EXPIRED": -1})


# ─── recorder over real handlers ─────────────────────────────────────────────

def test_every_handler_outcome_is_recorded_and_matches_the_audit_row(principal, db_query, audit_rows):
    junior, senior = principal("junior_alice"), principal("senior_carol")
    assert call_as(junior.token, server.get_account_profile, "ACC-001")["decision"] == "REDACT"
    assert call_as(senior.token, server.get_account_profile, "ACC-001")["decision"] == "ALLOW"
    assert call_as(senior.token, server.get_account_profile, "ACC-999")["decision"] == "BLOCK"
    assert call_as(junior.token, server.request_account_freeze, "ACC-010", "junior tries")["decision"] == "BLOCK"
    assert call_as(senior.token, server.query_transactions, "ACC-002", limit=0)["decision"] == "BLOCK"
    staged = call_as(senior.token, server.request_account_freeze, "ACC-010", "suspicious velocity")
    assert staged["decision"] == "ESCALATE"

    rows = _telemetry_rows(db_query)
    got = [(r["tool_name"], r["decision"], r["reason_code"]) for r in rows]
    assert got == [
        ("get_account_profile", "REDACT", None),
        ("get_account_profile", "ALLOW", None),
        ("get_account_profile", "BLOCK", "NOT_FOUND"),
        ("request_account_freeze", "BLOCK", "RBAC_BLOCK"),
        ("query_transactions", "BLOCK", "INVALID_INPUT"),
        ("request_account_freeze", "ESCALATE", "APPROVAL_CREATED"),
    ]
    assert all(type(r["latency_us"]) is int and r["latency_us"] >= 0 for r in rows)

    # telemetry mirrors the audit ledger exactly (decision + code), call for call
    audit = [(r["tool_name"], r["decision"], json.loads(r["detail"])["code"] if r["detail"] else None)
             for r in audit_rows()]
    assert audit == got


def test_telemetry_never_contains_args_pii_or_tokens(principal, db_query):
    senior, junior = principal("senior_carol"), principal("junior_alice")
    secrets = ["ACC-001", "ACC-010", "123456784821", "AB-1234567", "card 4111111111111111 refund",
               senior.token, junior.token, senior.sub, junior.sub, senior.tenant_id]
    call_as(senior.token, server.get_account_profile, "ACC-001")
    call_as(junior.token, server.get_account_profile, "ACC-001")
    call_as(senior.token, server.request_account_freeze, "ACC-010", "card 4111111111111111 refund")
    call_as(junior.token, server.query_transactions, "ACC-001'; DROP TABLE x;--")
    rows = _telemetry_rows(db_query)
    assert len(rows) == 4
    blob = json.dumps(rows)
    for s in secrets:
        assert s not in blob, s
    for token_part in senior.token.split("."):
        assert token_part not in blob


def test_db_refuses_non_code_values_even_if_domain_is_bypassed():
    bad = [("get account", "ALLOW", None), ("get_account_profile", "MAYBE", None),
           ("get_account_profile", "BLOCK", "Account ACC-001 not found"), ("get_account_profile", "BLOCK", "NOT_F0UND")]
    with get_connection() as conn:
        for tool, decision, code in bad:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO tool_telemetry (recorded_at, tool_name, decision, reason_code, latency_us) "
                             "VALUES ('x', ?, ?, ?, 1)", (tool, decision, code))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO tool_telemetry (recorded_at, tool_name, decision, reason_code, latency_us) "
                         "VALUES ('x', 'get_account_profile', 'ALLOW', NULL, 1.5)")


def test_handler_crash_is_recorded_as_error_and_still_raises(principal, db_query, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("db exploded with ACC-001")
    monkeypatch.setattr(server, "get_account", boom)
    with pytest.raises(RuntimeError):
        call_as(principal("senior_carol").token, server.get_account_profile, "ACC-001")
    rows = _telemetry_rows(db_query)
    assert [(r["decision"], r["reason_code"]) for r in rows] == [("ERROR", rules.UNHANDLED_EXCEPTION)]


def test_telemetry_failure_never_changes_the_tool_result(principal, db_query, monkeypatch, caplog):
    def broken(_rec):
        raise sqlite3.OperationalError("disk full")
    monkeypatch.setattr(store, "insert_record", broken)
    res = call_as(principal("senior_carol").token, server.get_account_profile, "ACC-001")
    assert res["decision"] == "ALLOW"
    assert _telemetry_rows(db_query) == []
    assert "telemetry record dropped for tool get_account_profile" in caplog.text


def test_wrapped_handlers_keep_their_advertised_schemas():
    async def _schemas():
        return {t.name: t.input_schema for t in await server.mcp.list_tools()}
    schemas = asyncio.run(_schemas())
    assert set(schemas["request_fee_refund"]["properties"]) == {
        "transaction_id", "amount_cents", "reason", "idempotency_key"}
    assert schemas["query_transactions"]["properties"]["limit"]["maximum"] == 100


# ─── SDK-level argument rejections ───────────────────────────────────────────

def test_sdk_argument_rejection_is_audited_and_recorded(principal, db_query, audit_rows):
    senior = principal("senior_carol")

    async def _call(args: dict) -> None:
        with authenticated(senior.token):
            await server.mcp.call_tool("request_fee_refund", args)

    leaked = "TXN-4111111111111111"
    with pytest.raises(ToolError):
        asyncio.run(_call({"transaction_id": leaked, "amount_cents": -5, "reason": "x"}))

    rows = _telemetry_rows(db_query)
    assert [(r["tool_name"], r["decision"], r["reason_code"]) for r in rows] == [
        ("request_fee_refund", "BLOCK", rules.SDK_ARGS_REJECTED)]
    audit = audit_rows("request_fee_refund")
    assert len(audit) == 1 and audit[0]["decision"] == "BLOCK"
    assert json.loads(audit[0]["detail"]) == {"code": rules.SDK_ARGS_REJECTED}
    assert (audit[0]["session_sub"], audit[0]["tenant_id"]) == (senior.sub, senior.tenant_id)
    assert leaked not in json.dumps(audit) + json.dumps(rows)


def test_sdk_unknown_tool_and_unauthenticated_rejection(db_query, audit_rows):
    async def _call(name: str, args: dict) -> None:
        await server.mcp.call_tool(name, args)

    with pytest.raises(ToolError, match="Unknown tool"):
        asyncio.run(_call("drop_all_tables", {}))
    assert _telemetry_rows(db_query) == [] and audit_rows() == []  # caller text is not recorded

    with pytest.raises(ToolError):
        asyncio.run(_call("get_account_profile", {"account_id": 12}))
    audit = audit_rows("get_account_profile")
    assert [(r["session_sub"], r["decision"]) for r in audit] == [("unknown", "BLOCK")]


# ─── T24 dashboard read model ────────────────────────────────────────────────

def test_dashboard_turnaround_and_expiry(principal, plant_approval, approve_as):
    senior, officer = principal("senior_carol"), principal("officer_eve")
    tenant = senior.tenant_id

    executed = plant_approval(senior, "request_account_freeze", {"account_id": "ACC-010", "reason": "velocity"})
    approve_as("officer_eve", executed)
    assert call_as(officer.token, server.execute_approved_action, executed)["result"].startswith("Account frozen")

    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat(timespec="microseconds")
    plant_approval(senior, "request_account_freeze", {"account_id": "ACC-011", "reason": "stale"}, expires_at=past)
    assert four_eyes.sweep_expired(tenant) == 1
    call_as(senior.token, server.get_account_profile, "ACC-999")  # one BLOCK

    dash = ops.dashboard(tenant)
    assert dash.turnaround is not None and dash.turnaround.count == 1
    assert Decimal(0) <= dash.turnaround.median_s == dash.turnaround.p95_s < Decimal(60)
    assert dash.expiry_rate == Decimal("0.5") and dash.terminal_approvals == 2
    assert ("NOT_FOUND", 1) in dash.blocked
    assert {s.tool for s in dash.latency} >= {"execute_approved_action", "get_account_profile"}

    other = ops.dashboard("tenant_b2b_cards")  # Four-Eyes metrics are tenant-scoped
    assert other.turnaround is None and other.expiry_rate is None
