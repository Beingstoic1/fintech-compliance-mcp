import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure repository root is on sys.path so `src...` imports work regardless of launch command
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP

from src.db.database import (
    get_account, get_transactions, detect_structuring,
    get_pending_approvals, get_approval, create_approval,
    update_approval_status, atomic_consume_approval,
    freeze_account, refund_transaction,
)
from src.db.audit import log_event
from src.security.session import SessionRegistry, DEMO_TOKENS
from src.security.guardrails import (
    pre_check, compute_args_sha256, canonical_json, post_process,
)

mcp = FastMCP("fintech-compliance")


@mcp.tool()
def get_account_profile(session_token: str, account_id: str) -> dict:
    """Get full account profile. Output is PII-masked for junior_analyst role."""
    tool_name = "get_account_profile"
    args = {"account_id": account_id}
    try:
        session = pre_check(session_token, tool_name, args)
    except (ValueError, PermissionError) as e:
        log_event("unknown", "unknown", "unknown", tool_name,
                  compute_args_sha256(tool_name, args, "unknown"), "BLOCK", str(e))
        return {"error": str(e), "decision": "BLOCK"}

    args_sha256 = compute_args_sha256(tool_name, args, session.sub)
    account = get_account(account_id, session.tenant_id)
    if not account:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "Account not found")
        return {"error": "Account not found", "decision": "BLOCK"}

    result = post_process(account, session, tool_name, args_sha256)
    log_event(session.sub, session.actor_role, session.tenant_id,
              tool_name, args_sha256, result["decision"])
    return result


@mcp.tool()
def query_transactions(session_token: str, account_id: str,
                       start_date: str = "", end_date: str = "",
                       limit: int = 50) -> dict:
    """Query transactions for an account. Memos and account refs masked for junior_analyst."""
    tool_name = "query_transactions"
    args = {"account_id": account_id}
    try:
        session = pre_check(session_token, tool_name, args)
    except (ValueError, PermissionError) as e:
        log_event("unknown", "unknown", "unknown", tool_name,
                  compute_args_sha256(tool_name, args, "unknown"), "BLOCK", str(e))
        return {"error": str(e), "decision": "BLOCK"}

    args_sha256 = compute_args_sha256(tool_name, args, session.sub)
    account = get_account(account_id, session.tenant_id)
    if not account:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "Account not found in your tenant scope")
        return {"error": "Account not found in your tenant scope", "decision": "BLOCK"}

    txns = get_transactions(account_id, start_date or None, end_date or None, min(limit, 100), tenant_id=session.tenant_id)
    result = post_process(txns, session, tool_name, args_sha256)
    log_event(session.sub, session.actor_role, session.tenant_id,
              tool_name, args_sha256, result["decision"])
    return result


@mcp.tool()
def detect_structuring_anomalies(session_token: str, tenant_id: str,
                                  threshold_cents: int = 999900) -> dict:
    """Detect sub-threshold structuring / smurfing ring patterns for a tenant."""
    tool_name = "detect_structuring_anomalies"
    args = {"tenant_id": tenant_id, "threshold_cents": threshold_cents}
    try:
        session = pre_check(session_token, tool_name, args)
    except (ValueError, PermissionError) as e:
        log_event("unknown", "unknown", "unknown", tool_name,
                  compute_args_sha256(tool_name, args, "unknown"), "BLOCK", str(e))
        return {"error": str(e), "decision": "BLOCK"}

    args_sha256 = compute_args_sha256(tool_name, args, session.sub)
    if tenant_id != session.tenant_id:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK",
                  f"TENANT_ISOLATION_VIOLATION: caller tenant {session.tenant_id} cannot query {tenant_id}")
        return {"error": "TENANT_ISOLATION_VIOLATION: caller tenant does not match target tenant",
                "decision": "BLOCK"}

    anomalies = detect_structuring(tenant_id, threshold_cents)
    result = post_process(anomalies, session, tool_name, args_sha256)
    log_event(session.sub, session.actor_role, session.tenant_id,
              tool_name, args_sha256, result["decision"])
    return result


@mcp.tool()
def request_account_freeze(session_token: str, account_id: str, reason: str) -> dict:
    """
    senior_investigator only. Creates a 15-minute approval gate for account freeze.
    Returns approval_id for the compliance_officer to act on.
    """
    tool_name = "request_account_freeze"
    args = {"account_id": account_id, "reason": reason}
    try:
        session = pre_check(session_token, tool_name, args)
    except (ValueError, PermissionError) as e:
        log_event("unknown", "unknown", "unknown", tool_name,
                  compute_args_sha256(tool_name, args, "unknown"), "BLOCK", str(e))
        return {"error": str(e), "decision": "BLOCK"}

    args_sha256 = compute_args_sha256(tool_name, args, session.sub)
    account = get_account(account_id, session.tenant_id)
    if not account:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "Account not found in your tenant scope")
        return {"error": "Account not found in your tenant scope", "decision": "BLOCK"}

    can_args = canonical_json(args)
    approval_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    create_approval(approval_id, session.sub, session.actor_role,
                    tool_name, can_args, args_sha256, expires_at,
                    tenant_id=session.tenant_id)
    log_event(session.sub, session.actor_role, session.tenant_id,
              tool_name, args_sha256, "ESCALATE",
              f"Approval created: {approval_id}")
    return {
        "approval_id": approval_id,
        "expires_in_seconds": 900,
        "status": "PENDING",
        "decision": "ESCALATE",
        "message": "Approval request created. A compliance_officer must approve before execution.",
    }


@mcp.tool()
def request_fee_refund(session_token: str, transaction_id: str,
                       amount_cents: int, reason: str) -> dict:
    """
    senior_investigator only. Creates a 15-minute approval gate for a fee refund.
    Returns approval_id for the compliance_officer to act on.
    """
    tool_name = "request_fee_refund"
    args = {"transaction_id": transaction_id, "amount_cents": amount_cents, "reason": reason}
    try:
        session = pre_check(session_token, tool_name, args)
    except (ValueError, PermissionError) as e:
        log_event("unknown", "unknown", "unknown", tool_name,
                  compute_args_sha256(tool_name, args, "unknown"), "BLOCK", str(e))
        return {"error": str(e), "decision": "BLOCK"}

    args_sha256 = compute_args_sha256(tool_name, args, session.sub)
    can_args = canonical_json(args)
    approval_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    create_approval(approval_id, session.sub, session.actor_role,
                    tool_name, can_args, args_sha256, expires_at,
                    tenant_id=session.tenant_id)
    log_event(session.sub, session.actor_role, session.tenant_id,
              tool_name, args_sha256, "ESCALATE",
              f"Refund approval created: {approval_id}")
    return {
        "approval_id": approval_id,
        "expires_in_seconds": 900,
        "status": "PENDING",
        "decision": "ESCALATE",
        "message": "Refund approval request created. A compliance_officer must approve before execution.",
    }


@mcp.tool()
def execute_approved_action(session_token: str, approval_id: str) -> dict:
    """
    compliance_officer only. Executes a previously approved action with Four-Eyes enforcement.
    Verifies: approval status=PENDING, not expired, arg hash match, four-eyes (no self-approval),
    tenant isolation, and atomically consumes the approval to prevent TOCTOU races.
    """
    tool_name = "execute_approved_action"
    args = {"approval_id": approval_id}
    try:
        session = pre_check(session_token, tool_name, args)
    except (ValueError, PermissionError) as e:
        log_event("unknown", "unknown", "unknown", tool_name,
                  compute_args_sha256(tool_name, args, "unknown"), "BLOCK", str(e))
        return {"error": str(e), "decision": "BLOCK"}

    args_sha256 = compute_args_sha256(tool_name, args, session.sub)

    # Fetch approval
    approval = get_approval(approval_id)
    if not approval:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "Approval not found")
        return {"error": "Approval not found", "decision": "BLOCK"}

    # Check status
    if approval["status"] not in ("PENDING", "APPROVED"):
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK",
                  f"Approval status is {approval['status']}, not PENDING/APPROVED")
        return {"error": f"ALREADY_{approval['status']}: approval cannot be executed",
                "decision": "BLOCK"}

    # Check expiry
    if datetime.now(timezone.utc).isoformat() > approval["expires_at"]:
        update_approval_status(approval_id, "EXPIRED")
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "Approval expired")
        return {"error": "EXPIRED: approval has passed its 15-minute TTL", "decision": "BLOCK"}

    # Four-Eyes enforcement
    if approval["requester_sub"] == session.sub:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "DUAL_CONTROL_VIOLATION: self-approval attempt")
        return {"error": "DUAL_CONTROL_VIOLATION: compliance_officer cannot approve their own request",
                "decision": "BLOCK"}

    # Tenant isolation enforcement (F4)
    approval_tenant = approval.get("tenant_id")
    if approval_tenant and approval_tenant != session.tenant_id:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK",
                  f"TENANT_ISOLATION: approval tenant {approval_tenant} != session tenant {session.tenant_id}")
        return {"error": "TENANT_ISOLATION_VIOLATION: approval belongs to a different tenant",
                "decision": "BLOCK"}

    # Verify argument hash
    orig_args = json.loads(approval["canonical_args_json"])
    expected_sha256 = compute_args_sha256(
        approval["tool_name"], orig_args, approval["requester_sub"]
    )
    if expected_sha256 != approval["args_sha256"]:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "ARGUMENT_HASH_MISMATCH")
        return {"error": "ARGUMENT_HASH_MISMATCH: approval binding invalid", "decision": "BLOCK"}

    # Atomically consume the approval (F1 — prevents TOCTOU race)
    consumed_at = datetime.now(timezone.utc).isoformat()
    was_consumed = atomic_consume_approval(approval_id, session.sub, consumed_at)
    if not was_consumed:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK",
                  "RACE_CONDITION: approval was already consumed by concurrent request")
        return {"error": "ALREADY_CONSUMED: approval was consumed by a concurrent request",
                "decision": "BLOCK"}

    # Execute the actual action (F7 — wrap in try/except to prevent error leakage)
    action_tool = approval["tool_name"]
    action_result = {}
    try:
        if action_tool == "request_account_freeze":
            freeze_account(orig_args["account_id"])
            action_result = {
                "result": "Account frozen successfully",
                "account_id": orig_args["account_id"],
            }
        elif action_tool == "request_fee_refund":
            new_txn_id = refund_transaction(
                orig_args["transaction_id"], orig_args["amount_cents"]
            )
            action_result = {
                "result": "Refund processed successfully",
                "new_txn_id": new_txn_id,
                "amount_cents": orig_args["amount_cents"],
            }
        else:
            action_result = {"result": f"Unknown action: {action_tool}"}
    except Exception:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "ERROR",
                  f"Action execution failed for {action_tool}")
        return {"error": "ACTION_EXECUTION_FAILED: internal error during action execution",
                "decision": "BLOCK"}

    log_event(session.sub, session.actor_role, session.tenant_id,
              tool_name, args_sha256, "EXECUTED",
              f"Executed {action_tool} for approval {approval_id}")

    return {
        "decision": "EXECUTED",
        "approval_id": approval_id,
        "action": action_tool,
        "approved_by": session.sub,
        "original_requester": approval["requester_sub"],
        **action_result,
    }


if __name__ == "__main__":
    mcp.run()
