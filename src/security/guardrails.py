"""Pre/post execution guardrails shared by every adapter.

* ``pre_check(tool)``: resolves the verified caller from the transport (never from
  tool arguments) and enforces RBAC.
* ``post_process(...)``: per-role field projection + untrusted-text envelopes
  (rules live in ``src.domain.policy``).
"""
from __future__ import annotations

import json
from typing import Any

from src.domain.policy import RBAC_MATRIX, detect_injection_signals, is_allowed, project  # noqa: F401
from src.security.binding import audit_digest  # noqa: F401  (keyed digest for audit rows)
from src.security.identity import Principal, current_principal


def canonical_json(args_dict: dict) -> str:
    """json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=True)"""
    return json.dumps(args_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def pre_check(tool_name: str) -> Principal:
    """Resolve the transport-bound principal and enforce RBAC.

    Raises AuthenticationError (a ValueError) with 'UNAUTHENTICATED', or
    PermissionError with 'RBAC_BLOCK' (the caller's role is not echoed back).
    """
    principal = current_principal()
    if not is_allowed(principal.role, tool_name):
        raise PermissionError(f"RBAC_BLOCK: caller is not permitted to call '{tool_name}'")
    return principal


def post_process(result: Any, principal: Principal, tool_name: str, args_digest: str) -> dict:
    projected, redacted = project(result, tool_name, principal.role)
    return {
        "data": projected,
        "decision": "REDACT" if redacted else "ALLOW",
        "session_sub": principal.sub,
        "actor_role": principal.role,
        "tenant_id": principal.tenant_id,
        "args_digest": args_digest,
    }
