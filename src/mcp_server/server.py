"""Fintech Compliance MCP server.

Identity is bound at the transport (T04): Streamable-HTTP bearer JWTs verified by
``JWTTokenVerifier``, or an operator-supplied token for stdio. No tool accepts a
session token, user id, role, or tenant id as an argument.

Telemetry (T23): every handler is wrapped by ``instrument_tool`` (latency, audited
decision, reason code). Arguments the SDK rejects before a handler runs are caught
in ``AuditedMCPServer.call_tool`` and recorded there: one BLOCK audit row
(``SDK_ARGS_REJECTED``, keyed args digest, real caller when authenticated) plus a
telemetry record. Calls to unknown tool names are not recorded: the name is caller
text and has no place in either store (the SDK logs and rejects them).
"""
import os
import sys
import time
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path so `src...` imports work regardless of launch command
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp.server.auth.settings import AuthSettings  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.mcpserver.context import Context  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError  # noqa: E402
from mcp_types import CallToolResult, InputRequiredResult  # noqa: E402
from pydantic import AnyHttpUrl, ValidationError  # noqa: E402

from src.db.audit import log_event  # noqa: E402
from src.db.database import detect_structuring, get_account, get_transactions  # noqa: E402
from src.domain.telemetry import SDK_ARGS_REJECTED  # noqa: E402
from src.mcp_server.schemas import (  # noqa: E402
    TOOL_INPUTS,
    AccountId,
    AmountCents,
    ApprovalId,
    DateBound,
    IdempotencyKey,
    QueryLimit,
    Reason,
    ThresholdCents,
    TransactionId,
)
from src.security.binding import audit_digest  # noqa: E402
from src.security.guardrails import post_process, pre_check  # noqa: E402
from src.security.identity import (  # noqa: E402
    ISSUER,
    AuthenticationError,
    JWTTokenVerifier,
    Principal,
    current_principal,
    enable_stdio_identity,
)
from src.services import approvals as four_eyes  # noqa: E402
from src.services.telemetry import instrument_tool, record_sdk_rejection  # noqa: E402

RESOURCE_URL = os.environ.get("FINTECH_MCP_RESOURCE_URL", "http://localhost:8000/mcp")



def _audit_sdk_rejection(tool_name: str, raw_args: dict[str, Any]) -> None:
    """BLOCK row for arguments the SDK refused. Only a keyed digest of the args is kept."""
    try:
        p = current_principal()
        sub, role, tenant = p.sub, p.role, p.tenant_id
    except AuthenticationError:
        sub = role = tenant = "unknown"
    log_event(sub, role, tenant, tool_name, audit_digest(tool_name, raw_args, sub), "BLOCK", SDK_ARGS_REJECTED)


class AuditedMCPServer(MCPServer[Any]):
    """Closes the gap where SDK-level argument rejections left no audit or telemetry trace."""

    async def call_tool(self, name: str, arguments: dict[str, Any],
                        context: Context[Any, Any] | None = None) -> CallToolResult | InputRequiredResult:
        start = time.perf_counter_ns()
        try:
            return await super().call_tool(name, arguments, context)
        except ToolError as exc:
            sdk_rejected = (not isinstance(exc, UnexpectedToolError)
                            and isinstance(exc.__cause__, ValidationError)
                            and name in TOOL_INPUTS)
            if sdk_rejected:
                _audit_sdk_rejection(name, arguments)
                record_sdk_rejection(name, start)
            raise


mcp = AuditedMCPServer(
    "fintech-compliance",
    token_verifier=JWTTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ISSUER),
        resource_server_url=AnyHttpUrl(RESOURCE_URL),
        validate_token_resource=False,  # JWTTokenVerifier enforces `aud` itself
    ),
)


def _guard(tool_name: str, raw_args: dict[str, Any]) -> tuple[Principal, Any, str] | dict[str, Any]:
    """Authenticate, authorize, and strictly validate. Returns a BLOCK dict on failure."""
    try:
        principal = pre_check(tool_name)
    except (ValueError, PermissionError) as e:
        code = "UNAUTHENTICATED" if isinstance(e, ValueError) else "RBAC_BLOCK"
        log_event("unknown", "unknown", "unknown", tool_name,
                  audit_digest(tool_name, raw_args, "unknown"), "BLOCK", code)
        return {"error": str(e), "decision": "BLOCK"}

    try:
        model = TOOL_INPUTS[tool_name].model_validate(raw_args)
    except ValidationError as e:
        fields = sorted({".".join(str(p) for p in err["loc"]) or "<root>" for err in e.errors()})
        log_event(principal.sub, principal.role, principal.tenant_id, tool_name,
                  audit_digest(tool_name, raw_args, principal.sub), "BLOCK", "INVALID_INPUT")
        return {"error": f"INVALID_INPUT: {', '.join(fields)}", "decision": "BLOCK"}

    return principal, model, audit_digest(tool_name, model.model_dump(), principal.sub)


def _block(p: Principal, tool_name: str, args_digest: str, code: str, message: str) -> dict[str, Any]:
    log_event(p.sub, p.role, p.tenant_id, tool_name, args_digest, "BLOCK", code)
    return {"error": message, "decision": "BLOCK"}


@mcp.tool()
@instrument_tool
def get_account_profile(account_id: AccountId) -> dict[str, Any]:
    """Get an account profile in the caller's tenant. Fields are projected per role."""
    tool_name = "get_account_profile"
    g = _guard(tool_name, {"account_id": account_id})
    if isinstance(g, dict):
        return g
    p, args, h = g

    account = get_account(args.account_id, p.tenant_id)
    if not account:
        return _block(p, tool_name, h, "NOT_FOUND", "Account not found")

    result = post_process(account, p, tool_name, h)
    log_event(p.sub, p.role, p.tenant_id, tool_name, h, result["decision"])
    return result


@mcp.tool()
@instrument_tool
def query_transactions(account_id: AccountId, start_date: DateBound = "",
                       end_date: DateBound = "", limit: QueryLimit = 50) -> dict[str, Any]:
    """Query an account's transactions (caller's tenant only). Memos are returned as untrusted text."""
    tool_name = "query_transactions"
    g = _guard(tool_name, {"account_id": account_id, "start_date": start_date,
                           "end_date": end_date, "limit": limit})
    if isinstance(g, dict):
        return g
    p, args, h = g

    if not get_account(args.account_id, p.tenant_id):
        return _block(p, tool_name, h, "NOT_FOUND", "Account not found in your tenant scope")

    txns = get_transactions(args.account_id, args.start_date or None, args.end_date or None,
                            args.limit, tenant_id=p.tenant_id)
    result = post_process(txns, p, tool_name, h)
    log_event(p.sub, p.role, p.tenant_id, tool_name, h, result["decision"])
    return result


@mcp.tool()
@instrument_tool
def detect_structuring_anomalies(threshold_cents: ThresholdCents = 999900) -> dict[str, Any]:
    """Detect sub-threshold structuring / smurfing rings in the caller's tenant."""
    tool_name = "detect_structuring_anomalies"
    g = _guard(tool_name, {"threshold_cents": threshold_cents})
    if isinstance(g, dict):
        return g
    p, args, h = g

    anomalies = detect_structuring(p.tenant_id, args.threshold_cents)
    result = post_process(anomalies, p, tool_name, h)
    log_event(p.sub, p.role, p.tenant_id, tool_name, h, result["decision"])
    return result


_ACTION_FIELDS = {"idempotency_key"}  # transport concerns, not part of the bound action


@mcp.tool()
@instrument_tool
def request_account_freeze(account_id: AccountId, reason: Reason,
                           idempotency_key: IdempotencyKey | None = None) -> dict[str, Any]:
    """senior_investigator only. Stages a 15-minute Four-Eyes approval for an account freeze.
    Pass an idempotency_key to make retries safe (same key + same args -> same approval_id)."""
    tool_name = "request_account_freeze"
    g = _guard(tool_name, {"account_id": account_id, "reason": reason,
                           "idempotency_key": idempotency_key})
    if isinstance(g, dict):
        return g
    p, args, h = g
    return four_eyes.stage_freeze(p, args.model_dump(exclude=_ACTION_FIELDS), h, args.idempotency_key)


@mcp.tool()
@instrument_tool
def request_fee_refund(transaction_id: TransactionId, amount_cents: AmountCents, reason: Reason,
                       idempotency_key: IdempotencyKey | None = None) -> dict[str, Any]:
    """senior_investigator only. Stages a 15-minute Four-Eyes approval for a fee refund
    (amount in minor units; must not exceed the transaction's refundable balance)."""
    tool_name = "request_fee_refund"
    g = _guard(tool_name, {"transaction_id": transaction_id, "amount_cents": amount_cents,
                           "reason": reason, "idempotency_key": idempotency_key})
    if isinstance(g, dict):
        return g
    p, args, h = g
    return four_eyes.stage_refund(p, args.model_dump(exclude=_ACTION_FIELDS), h, args.idempotency_key)


@mcp.tool()
@instrument_tool
def execute_approved_action(approval_id: ApprovalId,
                            idempotency_key: IdempotencyKey | None = None) -> dict[str, Any]:
    """
    compliance_officer only. Executes an action a human officer has already APPROVED
    (step-up sign-off happens in the approval console, never through this server).
    Consume + action + audit commit atomically; a retry with the same idempotency_key
    returns the original result.
    """
    tool_name = "execute_approved_action"
    g = _guard(tool_name, {"approval_id": approval_id, "idempotency_key": idempotency_key})
    if isinstance(g, dict):
        return g
    p, args, h = g
    return four_eyes.execute(p, args.approval_id, h, args.idempotency_key)


@mcp.tool()
@instrument_tool
def reject_approved_action(approval_id: ApprovalId, reason: Reason) -> dict[str, Any]:
    """compliance_officer only. Rejects a PENDING or APPROVED request (fail-safe direction)."""
    tool_name = "reject_approved_action"
    g = _guard(tool_name, {"approval_id": approval_id, "reason": reason})
    if isinstance(g, dict):
        return g
    p, args, h = g
    return four_eyes.reject(p, args.approval_id, args.reason, h)


def main() -> None:
    transport = os.environ.get("FINTECH_MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        # stdio has no per-request auth: the operator binds one identity at launch.
        enable_stdio_identity()
        mcp.run()
    elif transport == "streamable-http":
        mcp.run("streamable-http",
                host=os.environ.get("FINTECH_MCP_HOST", "127.0.0.1"),
                port=int(os.environ.get("FINTECH_MCP_PORT", "8000")))
    else:
        raise SystemExit(f"Unsupported FINTECH_MCP_TRANSPORT: {transport}")


if __name__ == "__main__":
    main()
