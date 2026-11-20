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

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------

def _compute_entry_hash(
    prev_hash: str,
    timestamp_utc: str,
    session_sub: str,
    actor_role: str,
    tenant_id: str,
    tool_name: str,
    args_sha256: str,
    decision: str,
    detail: str | None = None,
) -> str:
    detail_str = detail if detail is not None else ""
    payload = "|".join(
        [prev_hash, timestamp_utc, session_sub, actor_role, tenant_id,
         tool_name, args_sha256, decision, detail_str]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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
            prev_hash, timestamp_utc, session_sub, actor_role, tenant_id,
            tool_name, args_sha256, decision, detail
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
    Detects hash tampering AND row deletions (event_id gaps).
    Returns {"ok": True} or {"ok": False, "corrupted_event_id": N, "reason": "..."}
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY event_id ASC"
        ).fetchall()

    if not rows:
        return {"ok": True}

    prev_hash = "GENESIS"
    prev_event_id = None

    for row in rows:
        row_dict = dict(row)
        event_id = row_dict["event_id"]

        # Detect row deletions: event_id gaps (non-consecutive)
        if prev_event_id is not None and event_id != prev_event_id + 1:
            return {
                "ok": False,
                "corrupted_event_id": event_id,
                "reason": (
                    f"event_id gap detected: expected {prev_event_id + 1}, "
                    f"got {event_id} (possible row deletion)"
                ),
            }

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

        # Recompute entry_hash from stored fields (now includes tenant_id + detail)
        expected_hash = _compute_entry_hash(
            row_dict["prev_hash"],
            row_dict["timestamp_utc"],
            row_dict["session_sub"],
            row_dict["actor_role"],
            row_dict["tenant_id"],
            row_dict["tool_name"],
            row_dict["args_sha256"],
            row_dict["decision"],
            row_dict["detail"],
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
        prev_event_id = event_id

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


# ---------------------------------------------------------------------------
# Module init
# ---------------------------------------------------------------------------
init_audit_table()
