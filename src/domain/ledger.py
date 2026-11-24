"""Pure audit-ledger rules (T09): canonical preimages and structured ``detail``.

No I/O and no keys: ``src.db.audit`` applies the HMAC over the bytes built here.

* Preimages are canonical JSON (sorted keys, no whitespace, ASCII), so field
  boundaries are unambiguous (the v1 ``"|".join`` preimage was not).
* ``detail`` is never free text: it is a machine code (``^[A-Z][A-Z_]{1,63}$``, no
  digits, so a PAN, phone number or ``str(e)`` cannot fit) plus a small allowlist of
  typed references. Anything else is replaced with ``INVALID_DETAIL``.

Threat model:
  * PII or secrets in evidence: ``normalize_detail`` turns any free text into
    ``INVALID_DETAIL``.
  * Preimage confusion: canonical JSON with explicit keys, so two different rows cannot
    produce the same bytes.
  * Signature reuse: checkpoint preimages carry a ``purpose`` tag, so an entry HMAC cannot
    be replayed as a checkpoint signature.
  * Not covered here: key custody (``src.security.keys``) and storage (``src.db.audit``).
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import Any

CHAIN_VERSION = 2
GENESIS = "GENESIS"
LEGACY_V1_PREFIX = "LEGACY-V1:"

DECISIONS = frozenset({
    "ALLOW", "REDACT", "BLOCK", "ESCALATE", "EXECUTED", "APPROVED", "REJECTED", "EXPIRED", "ERROR",
})

MAX_DETAIL_CHARS = 512
INVALID_DETAIL = {"code": "INVALID_DETAIL"}

_CODE = re.compile(r"^[A-Z][A-Z_]{1,63}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TOOL = re.compile(r"^[a-z][a-z_]{1,63}$")
_TXN = re.compile(r"^TXN-[A-Z0-9-]{1,40}$")


def _is_count(v: Any) -> bool:
    return type(v) is int and 0 <= v <= 1_000_000


REF_VALIDATORS: dict[str, Callable[[Any], bool]] = {
    "approval_id": lambda v: isinstance(v, str) and bool(_UUID.match(v)),
    "action": lambda v: isinstance(v, str) and bool(_TOOL.match(v)),
    "new_txn_id": lambda v: isinstance(v, str) and bool(_TXN.match(v)),
    "count": _is_count,
}


def canonical(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def normalize_detail(detail: str | Mapping[str, Any] | None) -> str | None:
    """Validate ``detail`` (a code, or ``{"code": ..., <allowlisted refs>}``) and
    return its canonical JSON. Invalid input fails closed to ``INVALID_DETAIL``."""
    if detail is None:
        return None
    obj = {"code": detail} if isinstance(detail, str) else dict(detail)
    ok = (
        isinstance(obj.get("code"), str) and bool(_CODE.match(obj["code"]))
        and all(k in REF_VALIDATORS and REF_VALIDATORS[k](v)
                for k, v in obj.items() if k != "code")
    )
    out = canonical(obj if ok else INVALID_DETAIL).decode()
    return out if len(out) <= MAX_DETAIL_CHARS else canonical(INVALID_DETAIL).decode()


def entry_preimage(*, event_id: int, prev_hash: str, timestamp_utc: str, session_sub: str,
                   actor_role: str, tenant_id: str, tool_name: str, args_digest: str,
                   decision: str, detail: str | None, key_id: str) -> bytes:
    """Bytes the audit HMAC covers for one row (v2: includes ``event_id``, ``prev`` and ``kid``)."""
    return canonical({
        "v": CHAIN_VERSION, "event_id": event_id, "prev": prev_hash, "ts": timestamp_utc,
        "sub": session_sub, "role": actor_role, "tenant": tenant_id, "tool": tool_name,
        "args": args_digest, "decision": decision, "detail": detail, "kid": key_id,
    })


def checkpoint_preimage(*, event_id: int, head: str, genesis: str, ts: str, key_id: str) -> bytes:
    """Domain-separated from entries by ``purpose``."""
    return canonical({
        "purpose": "audit-checkpoint", "v": CHAIN_VERSION, "event_id": event_id,
        "head": head, "genesis": genesis, "ts": ts, "kid": key_id,
    })
