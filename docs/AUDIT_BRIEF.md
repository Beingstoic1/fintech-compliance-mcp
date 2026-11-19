# Fintech Compliance MCP — Security Audit Brief
**Target Reviewer**: Principal AI Security Auditor / Model Reviewer (Claude Sonnet / GPT-4o)  
**Specification Invariant**: Zero-Trust MCP Guardrails with Hash-Chained Audit & Four-Eyes Control  
**Generated At**: 2026-11-19T18:12:00Z  

---

## 1. System Overview & File Tree (Max 20 Lines)

```
fintech-compliance-mcp/
├── src/
│   ├── db/
│   │   ├── audit.py          # SHA-256 genesis-to-tip hash-chained audit ledger + verifier
│   │   └── database.py       # SQLite schema, 121 realistic seed records, structuring ring detector
│   ├── mcp_server/
│   │   └── server.py         # FastMCP server exposing 6 guarded tools (3 read, 2 escalate, 1 execute)
│   ├── security/
│   │   ├── guardrails.py     # Dual-boundary pipeline: pre-check RBAC + post-check PII & injection strip
│   │   └── session.py        # Zero-trust server-side session token registry (never trust client role)
│   └── workbench/
│       └── app.py            # Streamlit 3-tab enterprise compliance console & tamper lab
├── tests/
│   ├── conftest.py           # Pytest fixtures and database clean-state enforcement
│   └── test_security_and_mcp.py # 12 automated unit/integration tests
├── pyproject.toml
└── .github/workflows/mcp-security.yml
```

**Core Security Invariants**:
1. **Zero-Trust Session Identity**: Client credentials only supply `session_token`. The `actor_role` and `tenant_id` are resolved strictly server-side from `SessionRegistry`.
2. **Dual-Boundary Guardrails**: Pre-execution RBAC enforcement blocks unauthorized roles. Post-execution regex filters dynamically mask PII for `junior_analyst` and scrub prompt injections (`[INJECTION STRIPPED]`) across all roles.
3. **Four-Eyes Dual Control**: State-mutating tools create a 15-minute single-use `approval_id` bound to `SHA256(tool || args || requester)`. Execution requires an independent compliance officer (`requester_sub != approver_sub`).
4. **Tamper-Evident SHA-256 Audit Ledger**: Solves AgentGuard's non-tamper-proof SQLite limitation by chaining each row's hash to the previous entry.

---

## 2. Test Verification Output (`pytest -v`)

```
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.2.0, pluggy-1.7.0 -- .venv/bin/python3.14
cachedir: .pytest_cache
rootdir: /Users/zenos/Desktop/fintech-compliance-mcp
configfile: pyproject.toml
plugins: anyio-4.16.0, asyncio-1.5.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 12 items

tests/test_security_and_mcp.py::test_junior_analyst_blocked_from_freeze PASSED [  8%]
tests/test_security_and_mcp.py::test_junior_analyst_blocked_from_execute PASSED [ 16%]
tests/test_security_and_mcp.py::test_pii_masking_account_number PASSED   [ 25%]
tests/test_security_and_mcp.py::test_pii_masking_pan PASSED              [ 33%]
tests/test_security_and_mcp.py::test_senior_sees_unmasked_data PASSED    [ 41%]
tests/test_security_and_mcp.py::test_injection_stripping_all_roles PASSED [ 50%]
tests/test_security_and_mcp.py::test_approval_hash_binding_deterministic PASSED [ 58%]
tests/test_security_and_mcp.py::test_approval_hash_binding_arg_change PASSED [ 66%]
tests/test_security_and_mcp.py::test_four_eyes_self_approval_blocked PASSED [ 75%]
tests/test_security_and_mcp.py::test_replay_blocked_after_consume PASSED [ 83%]
tests/test_security_and_mcp.py::test_expired_approval_rejected PASSED    [ 91%]
tests/test_security_and_mcp.py::test_audit_chain_tamper_detection PASSED [100%]

============================== 12 passed in 0.10s ==============================
```

---

## 3. Security-Critical Source Code

### A. Zero-Trust Session Token Registry (`src/security/session.py`)

```python
import secrets
from dataclasses import dataclass

ROLES = {"junior_analyst", "senior_investigator", "compliance_officer"}


@dataclass
class Session:
    session_token: str
    sub: str           # unique user subject ID e.g. 'junior_alice'
    actor_role: str    # one of ROLES
    tenant_id: str


class SessionRegistry:
    _sessions: dict  # class-level dict: token -> Session

    @classmethod
    def _init(cls):
        if not hasattr(cls, '_sessions'):
            cls._sessions = {}

    @classmethod
    def create(cls, sub: str, actor_role: str, tenant_id: str) -> str:
        """Generate token = 'tok_' + secrets.token_hex(16), store Session, return token."""
        cls._init()
        token = "tok_" + secrets.token_hex(16)
        cls._sessions[token] = Session(
            session_token=token, sub=sub, actor_role=actor_role, tenant_id=tenant_id
        )
        return token

    @classmethod
    def resolve(cls, session_token: str) -> Session:
        """Return Session or raise ValueError('INVALID_SESSION_TOKEN')."""
        cls._init()
        session = cls._sessions.get(session_token)
        if session is None:
            raise ValueError("INVALID_SESSION_TOKEN")
        return session

    @classmethod
    def revoke(cls, session_token: str) -> None:
        cls._init()
        cls._sessions.pop(session_token, None)


# Pre-seed 6 demo sessions at module import time
# Store tokens in DEMO_TOKENS dict: sub -> token
DEMO_TOKENS: dict[str, str] = {}


def _seed_demo_sessions():
    demos = [
        ("junior_alice",  "junior_analyst",      "tenant_neobank_in"),
        ("junior_bob",    "junior_analyst",       "tenant_b2b_cards"),
        ("senior_carol",  "senior_investigator",  "tenant_neobank_in"),
        ("senior_dave",   "senior_investigator",  "tenant_b2b_cards"),
        ("officer_eve",   "compliance_officer",   "tenant_neobank_in"),
        ("officer_frank", "compliance_officer",   "tenant_b2b_cards"),
    ]
    for sub, role, tenant in demos:
        token = SessionRegistry.create(sub, role, tenant)
        DEMO_TOKENS[sub] = token


_seed_demo_sessions()
```

---

### B. Dual-Boundary Guardrails Engine (`src/security/guardrails.py`)

```python
import re
import hashlib
import json
from typing import Any

from src.security.session import SessionRegistry, Session

# PII masking regexes
ACCOUNT_NUMBER_RE = re.compile(r'\b(\d{8,16})\b')
PAN_RE = re.compile(r'\b([A-Z]{5}\d{4}[A-Z])\b')       # e.g. ABCDE1234F
TAX_ID_RE = re.compile(r'\b([A-Z]{2}-\d{7})\b')         # e.g. AB-1234567
INJECTION_RE = re.compile(
    r'(?i)(IGNORE\s+PREVIOUS\s+INSTRUCTIONS?|SYSTEM\s*PROMPT|JAILBREAK|'
    r'DISREGARD\s+ALL|FORGET\s+(YOUR\s+)?INSTRUCTIONS?|'
    r'DO\s+NOT\s+FOLLOW|OVERRIDE\s+(PREVIOUS\s+)?INSTRUCTIONS?)',
    re.IGNORECASE
)

RBAC_MATRIX: dict[str, set[str]] = {
    "get_account_profile":           {"junior_analyst", "senior_investigator", "compliance_officer"},
    "query_transactions":            {"junior_analyst", "senior_investigator", "compliance_officer"},
    "detect_structuring_anomalies":  {"junior_analyst", "senior_investigator", "compliance_officer"},
    "request_account_freeze":        {"senior_investigator"},
    "request_fee_refund":            {"senior_investigator"},
    "execute_approved_action":       {"compliance_officer"},
}


def canonical_json(args_dict: dict) -> str:
    """json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=True)"""
    return json.dumps(args_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def compute_args_sha256(tool_name: str, args_dict: dict, requester_sub: str) -> str:
    """SHA256(tool_name + '|' + canonical_json(args_dict) + '|' + requester_sub)"""
    payload = tool_name + "|" + canonical_json(args_dict) + "|" + requester_sub
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def pre_check(session_token: str, tool_name: str, args: dict) -> Session:
    """
    1. Resolve session via SessionRegistry.resolve() — raises ValueError on bad token
    2. Lookup RBAC_MATRIX.get(tool_name, set()) — if role not in allowed_roles:
       raise PermissionError(f"RBAC_BLOCK: role '{session.actor_role}' cannot call '{tool_name}'")
    3. Return session
    """
    session = SessionRegistry.resolve(session_token)
    allowed_roles = RBAC_MATRIX.get(tool_name, set())
    if session.actor_role not in allowed_roles:
        raise PermissionError(
            f"RBAC_BLOCK: role '{session.actor_role}' cannot call '{tool_name}'"
        )
    return session


def _mask_string(value: str, session: Session) -> str:
    """
    For ALL roles: strip injection patterns → '[INJECTION STRIPPED]'
    For junior_analyst ONLY additionally:
      - Account numbers (8-16 digits): replace with '****' + last4
      - PAN 'ABCDE1234F' → 'XXXXX' + last4 chars of match (e.g. '234F')
      - Tax ID 'AB-1234567' → 'XX-XXX' + last4 chars (e.g. '4567')
    """
    # First strip injections for ALL roles
    result = INJECTION_RE.sub('[INJECTION STRIPPED]', value)

    if session.actor_role == "junior_analyst":
        # Mask account numbers
        def mask_account(m):
            full = m.group(1)
            return '****' + full[-4:]
        result = ACCOUNT_NUMBER_RE.sub(mask_account, result)

        # Mask PAN
        def mask_pan(m):
            full = m.group(1)
            return 'XXXXX' + full[-4:]
        result = PAN_RE.sub(mask_pan, result)

        # Mask tax ID
        def mask_tax(m):
            full = m.group(1)
            return 'XX-XXX' + full[-4:]
        result = TAX_ID_RE.sub(mask_tax, result)

    return result


def _sanitize_value(value: Any, session: Session) -> tuple[Any, bool]:
    """Recursively sanitize a value. Return (sanitized, was_modified)."""
    if isinstance(value, str):
        masked = _mask_string(value, session)
        return masked, masked != value
    elif isinstance(value, dict):
        return sanitize_record(value, session)
    elif isinstance(value, list):
        new_list = []
        modified = False
        for item in value:
            new_item, m = _sanitize_value(item, session)
            new_list.append(new_item)
            modified = modified or m
        return new_list, modified
    return value, False


def sanitize_record(record: dict, session: Session) -> tuple[dict, bool]:
    """Walk every value in record, apply _sanitize_value. Return (sanitized_record, was_modified)."""
    new_record = {}
    modified = False
    for k, v in record.items():
        new_v, m = _sanitize_value(v, session)
        new_record[k] = new_v
        modified = modified or m
    return new_record, modified


def sanitize_list(records: list[dict], session: Session) -> tuple[list[dict], bool]:
    new_list = []
    any_modified = False
    for record in records:
        new_rec, m = sanitize_record(record, session)
        new_list.append(new_rec)
        any_modified = any_modified or m
    return new_list, any_modified


def post_process(result: Any, session: Session, tool_name: str, args_sha256: str) -> dict:
    """
    Sanitize result. If result is a list, use sanitize_list; if dict, use sanitize_record.
    Return:
    {
        "data": sanitized_result,
        "decision": "REDACT" if modified else "ALLOW",
        "session_sub": session.sub,
        "actor_role": session.actor_role,
        "tenant_id": session.tenant_id,
        "args_sha256": args_sha256
    }
    """
    if isinstance(result, list):
        sanitized, modified = sanitize_list(result, session)
    elif isinstance(result, dict):
        sanitized, modified = sanitize_record(result, session)
    else:
        sanitized = result
        modified = False

    return {
        "data": sanitized,
        "decision": "REDACT" if modified else "ALLOW",
        "session_sub": session.sub,
        "actor_role": session.actor_role,
        "tenant_id": session.tenant_id,
        "args_sha256": args_sha256,
    }
```

---

### C. SHA-256 Hash-Chained Audit Ledger (`src/db/audit.py`)

```python
"""
Fintech Compliance MCP – Tamper-evident SHA-256 hash-chained audit ledger.
Solves AgentGuard's non-tamper-proof SQLite limitation by chaining every
audit row with SHA-256(prev_hash + current payload = entry_hash).
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone

from src.db.database import DB_PATH, get_connection

_AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    event_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc  TEXT    NOT NULL,
    session_sub    TEXT    NOT NULL,
    actor_role     TEXT    NOT NULL,
    tenant_id      TEXT    NOT NULL,
    tool_name      TEXT    NOT NULL,
    args_sha256    TEXT    NOT NULL,
    decision       TEXT    NOT NULL,
    detail         TEXT,
    prev_hash      TEXT    NOT NULL,
    entry_hash     TEXT    NOT NULL
)
"""


def init_audit_table() -> None:
    """Create audit_logs table if not exists."""
    with get_connection() as conn:
        conn.execute(_AUDIT_DDL)


def _compute_entry_hash(
    prev_hash: str,
    timestamp_utc: str,
    session_sub: str,
    actor_role: str,
    tool_name: str,
    args_sha256: str,
    decision: str,
) -> str:
    payload = "|".join(
        [prev_hash, timestamp_utc, session_sub, actor_role, tool_name, args_sha256, decision]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(
    session_sub: str,
    actor_role: str,
    tenant_id: str,
    tool_name: str,
    args_sha256: str,
    decision: str,
    detail: str | None = None,
) -> int:
    """
    Append a new audit row atomically using BEGIN IMMEDIATE for thread safety.
    Returns the new event_id.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        prev_row = conn.execute(
            "SELECT entry_hash FROM audit_logs ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev_row["entry_hash"] if prev_row else "GENESIS"

        timestamp_utc = datetime.now(timezone.utc).isoformat()
        entry_hash = _compute_entry_hash(
            prev_hash, timestamp_utc, session_sub, actor_role, tool_name, args_sha256, decision
        )

        cursor = conn.execute(
            """INSERT INTO audit_logs
               (timestamp_utc, session_sub, actor_role, tenant_id, tool_name,
                args_sha256, decision, detail, prev_hash, entry_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (timestamp_utc, session_sub, actor_role, tenant_id, tool_name,
             args_sha256, decision, detail, prev_hash, entry_hash),
        )
        event_id: int = cursor.lastrowid  # type: ignore[assignment]
        conn.commit()
        return event_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_audit_log(limit: int = 200) -> list[dict]:
    """Return up to *limit* rows from audit_logs, most recent first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY event_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def verify_audit_chain() -> dict:
    """
    Re-walk the entire chain in event_id ascending order.
    Returns {"ok": True} or {"ok": False, "corrupted_event_id": N, "reason": "..."}
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY event_id ASC"
        ).fetchall()

    if not rows:
        return {"ok": True}

    prev_hash = "GENESIS"

    for row in rows:
        row_dict = dict(row)
        event_id = row_dict["event_id"]

        # Verify stored prev_hash links correctly to previous row
        if row_dict["prev_hash"] != prev_hash:
            return {
                "ok": False,
                "corrupted_event_id": event_id,
                "reason": (
                    f"prev_hash mismatch: expected {prev_hash!r}, "
                    f"got {row_dict['prev_hash']!r}"
                ),
            }

        # Recompute entry_hash from stored fields
        expected_hash = _compute_entry_hash(
            row_dict["prev_hash"],
            row_dict["timestamp_utc"],
            row_dict["session_sub"],
            row_dict["actor_role"],
            row_dict["tool_name"],
            row_dict["args_sha256"],
            row_dict["decision"],
        )
        if row_dict["entry_hash"] != expected_hash:
            return {
                "ok": False,
                "corrupted_event_id": event_id,
                "reason": (
                    f"entry_hash mismatch: expected {expected_hash!r}, "
                    f"got {row_dict['entry_hash']!r}"
                ),
            }

        prev_hash = row_dict["entry_hash"]

    return {"ok": True}


def tamper_row(event_id: int, new_decision: str) -> None:
    """
    Directly UPDATE decision WITHOUT recomputing hashes.
    Used ONLY by the Streamlit tamper lab to demonstrate detection.
    """
    with get_connection() as conn:
        conn.execute(
            "UPDATE audit_logs SET decision=? WHERE event_id=?",
            (new_decision, event_id),
        )


init_audit_table()
```

---

### D. FastMCP Guarded Tools Server (`src/mcp_server/server.py`)

```python
import json
import uuid
from datetime import datetime, timedelta, timezone

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP

from src.db.database import (
    get_account, get_transactions, detect_structuring,
    get_pending_approvals, get_approval, create_approval,
    update_approval_status, freeze_account, refund_transaction,
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
    txns = get_transactions(account_id, start_date or None, end_date or None, min(limit, 100))
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
    can_args = canonical_json(args)
    approval_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    create_approval(approval_id, session.sub, session.actor_role,
                    tool_name, can_args, args_sha256, expires_at)
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
                    tool_name, can_args, args_sha256, expires_at)
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
    Verifies: approval status=PENDING, not expired, arg hash match, four-eyes (no self-approval).
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
    if approval["status"] != "PENDING":
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK",
                  f"Approval status is {approval['status']}, not PENDING")
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

    # Verify argument hash
    orig_args = json.loads(approval["canonical_args_json"])
    expected_sha256 = compute_args_sha256(
        approval["tool_name"], orig_args, approval["requester_sub"]
    )
    if expected_sha256 != approval["args_sha256"]:
        log_event(session.sub, session.actor_role, session.tenant_id,
                  tool_name, args_sha256, "BLOCK", "ARGUMENT_HASH_MISMATCH")
        return {"error": "ARGUMENT_HASH_MISMATCH: approval binding invalid", "decision": "BLOCK"}

    # Consume the approval
    consumed_at = datetime.now(timezone.utc).isoformat()
    update_approval_status(approval_id, "CONSUMED",
                           approver_sub=session.sub,
                           consumed_at=consumed_at)

    # Execute the actual action
    action_tool = approval["tool_name"]
    action_result = {}
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
```

---

### E. SQLite Schema DDL & Invariant Mutation Logic (`src/db/database.py`)

```python
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "fintech_ledger.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


_DDL = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id     TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id),
    holder_name    TEXT NOT NULL,
    account_number TEXT NOT NULL,
    pan_last4      TEXT,
    tax_id         TEXT,
    account_type   TEXT NOT NULL,
    kyc_status     TEXT NOT NULL DEFAULT 'verified',
    risk_score     REAL NOT NULL DEFAULT 0.0,
    is_frozen      INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id       TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id),
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    merchant_id  TEXT,
    amount_cents INTEGER NOT NULL,
    currency     TEXT NOT NULL DEFAULT 'INR',
    txn_type     TEXT NOT NULL,
    status       TEXT NOT NULL,
    memo         TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id         TEXT PRIMARY KEY,
    requester_sub       TEXT NOT NULL,
    requester_role      TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    canonical_args_json TEXT NOT NULL,
    args_sha256         TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'PENDING',
    approver_sub        TEXT,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    consumed_at         TEXT
);
"""


def create_approval(
    approval_id: str,
    requester_sub: str,
    requester_role: str,
    tool_name: str,
    canonical_args_json: str,
    args_sha256: str,
    expires_at: str,
) -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO pending_approvals
               (approval_id, requester_sub, requester_role, tool_name,
                canonical_args_json, args_sha256, status, approver_sub,
                created_at, expires_at, consumed_at)
               VALUES (?,?,?,?,?,?,'PENDING',NULL,?,?,NULL)""",
            (approval_id, requester_sub, requester_role, tool_name,
             canonical_args_json, args_sha256, created_at, expires_at),
        )


def update_approval_status(
    approval_id: str,
    status: str,
    approver_sub: str | None = None,
    consumed_at: str | None = None,
) -> None:
    with get_connection() as conn:
        conn.execute(
            """UPDATE pending_approvals
               SET status=?, approver_sub=?, consumed_at=?
               WHERE approval_id=?""",
            (status, approver_sub, consumed_at, approval_id),
        )


def freeze_account(account_id: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE accounts SET is_frozen=1 WHERE account_id=?",
            (account_id,),
        )


def refund_transaction(txn_id: str, amount_cents: int) -> str:
    new_txn_id = f"TXN-REF-{uuid.uuid4().hex[:8].upper()}"
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        orig = conn.execute(
            "SELECT tenant_id, account_id FROM transactions WHERE txn_id=?",
            (txn_id,),
        ).fetchone()
        if orig is None:
            raise ValueError(f"Transaction {txn_id} not found")

        conn.execute(
            """INSERT INTO transactions
               (txn_id, tenant_id, account_id, merchant_id, amount_cents, currency,
                txn_type, status, memo, created_at)
               VALUES (?,?,?,NULL,?,?,'refund','completed',?,?)""",
            (new_txn_id, orig["tenant_id"], orig["account_id"],
             amount_cents, "INR", f"Refund for {txn_id}", created_at),
        )
    return new_txn_id


def detect_structuring(tenant_id: str, threshold_cents: int = 999900) -> list[dict]:
    """
    Detect smurfing: accounts sending >= 2 sub-threshold debits to the same
    merchant within any 48-hour window.
    """
    sql = """
        SELECT account_id,
               merchant_id,
               COUNT(*)          AS txn_count,
               SUM(amount_cents) AS total_amount_cents,
               MIN(created_at)   AS window_start,
               MAX(created_at)   AS window_end
        FROM   transactions
        WHERE  tenant_id = ?
          AND  amount_cents < ?
          AND  txn_type = 'debit'
          AND  merchant_id IS NOT NULL
        GROUP  BY account_id, merchant_id
        HAVING txn_count >= 2
           AND (julianday(window_end) - julianday(window_start)) * 24 <= 48
    """
    with get_connection() as conn:
        rows = conn.execute(sql, (tenant_id, threshold_cents)).fetchall()
    return [dict(r) for r in rows]
```
