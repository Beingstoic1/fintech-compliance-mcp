"""Keyed argument binding (T08).

``args_digest = HMAC-SHA256(key[kid], canonical({tool, args, requester, tenant}))``

* Approvals store ``(key_id, args_digest)``; execution recomputes with the stored
  ``key_id``. Someone with DB write but no key cannot forge or re-point a binding
  (the old unkeyed check compared two columns of the same row).
* Audit rows use ``audit_digest`` (same key) so low-entropy identifiers such as
  ``ACC-001`` are pseudonymised, not trivially reversible.

Keys: ``FINTECH_BINDING_KEYS="kid1:secret1,kid2:secret2"`` plus
``FINTECH_BINDING_ACTIVE_KID`` (defaults to the first). Without them, a dev key is
created once at ``<db dir>/.binding_keys`` (mode 0600). See ``src.security.keys``.
"""
from __future__ import annotations

import json
from typing import Any

from src.security.keys import Keyring

_RING = Keyring.load(env="FINTECH_BINDING_KEYS", active_env="FINTECH_BINDING_ACTIVE_KID",
                     dev_file=".binding_keys", dev_prefix="dev")
ACTIVE_KID = _RING.active_kid


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def bind_args(tool_name: str, args: dict[str, Any], requester_sub: str, tenant_id: str) -> tuple[str, str]:
    """Return (key_id, digest) for a staged approval."""
    payload = {"tool": tool_name, "args": args, "requester": requester_sub, "tenant": tenant_id}
    return ACTIVE_KID, _RING.mac(ACTIVE_KID, _canonical(payload))


def verify_binding(key_id: str, digest: str, tool_name: str, args: dict[str, Any],
                   requester_sub: str, tenant_id: str) -> bool:
    """Constant-time check. Unknown key ids (e.g. legacy unkeyed rows) fail closed."""
    payload = {"tool": tool_name, "args": args, "requester": requester_sub, "tenant": tenant_id}
    return _RING.verify(key_id, _canonical(payload), digest)


def audit_digest(tool_name: str, args: dict[str, Any], sub: str) -> str:
    """Keyed pseudonymous digest of a call's arguments for the audit ledger."""
    try:
        payload = {"tool": tool_name, "args": args, "sub": sub}
        _canonical(payload)
    except (TypeError, ValueError):
        payload = {"tool": tool_name, "args": {"_unserializable": True}, "sub": sub}
    return _RING.mac(ACTIVE_KID, _canonical(payload))
