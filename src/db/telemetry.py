"""Telemetry storage (T23) and the approval reads behind the T24 widgets.

``tool_telemetry`` is operational data, not evidence: it sits outside the audit
hash chain and has no tenant, subject, argument or token column. CHECK constraints
mirror the domain patterns, so the table refuses anything that is not a tool name,
a known decision, or a code-shaped reason even if a caller skips the domain layer.

Threat model:
  * Side channel: a raw INSERT of free text, an unknown decision or a REAL latency is
    refused by CHECK constraints, even when the domain layer is skipped.
  * Not covered: no tamper evidence and no retention limit; the dashboard reads a
    bounded window but the table grows.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from src.domain.ledger import DECISIONS
from src.domain.telemetry import TERMINAL_STATUSES, ToolCallRecord


def get_connection() -> sqlite3.Connection:
    # Imported per call: ``src.db.database`` runs ``init_db()`` at import time, which
    # creates this module's table, so a module-level import would be circular.
    """Connection to the main ledger DB (imported lazily to avoid an import cycle)."""
    from src.db.database import get_connection as _get_connection
    return _get_connection()


DEFAULT_WINDOW = 5000  # most recent calls the dashboard aggregates over

_DECISIONS_SQL = ",".join(f"'{d}'" for d in sorted(DECISIONS))

_DDL = f"""
CREATE TABLE IF NOT EXISTS tool_telemetry (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at  TEXT    NOT NULL,
    tool_name    TEXT    NOT NULL
        CHECK (length(tool_name) BETWEEN 2 AND 64 AND tool_name NOT GLOB '*[^a-z_]*'),
    decision     TEXT    NOT NULL CHECK (decision IN ({_DECISIONS_SQL})),
    reason_code  TEXT
        CHECK (reason_code IS NULL OR (length(reason_code) BETWEEN 2 AND 64
                                       AND reason_code NOT GLOB '*[^A-Z_]*')),
    latency_us   INTEGER NOT NULL CHECK (typeof(latency_us) = 'integer' AND latency_us >= 0)
);
CREATE INDEX IF NOT EXISTS idx_tool_telemetry_tool ON tool_telemetry (tool_name);
"""


def init_telemetry_table(conn: sqlite3.Connection | None = None) -> None:
    """Create ``tool_telemetry`` and its CHECK constraints if missing."""
    if conn is not None:
        conn.executescript(_DDL)
        return
    with get_connection() as own:
        own.executescript(_DDL)


def insert_record(rec: ToolCallRecord) -> None:
    """Store one already-sanitized ``ToolCallRecord``."""
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO tool_telemetry (recorded_at, tool_name, decision, reason_code, latency_us) "
                "VALUES (?, ?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(timespec="microseconds"), rec.tool, rec.decision,
                 rec.reason_code, rec.latency_us),
            )
    finally:
        conn.close()


def recent_records(limit: int = DEFAULT_WINDOW) -> list[ToolCallRecord]:
    """The newest ``limit`` telemetry records (all tenants; the table has no tenant column)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("INVALID_LIMIT")
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT tool_name, decision, reason_code, latency_us FROM tool_telemetry "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    return [ToolCallRecord(r["tool_name"], r["decision"], r["reason_code"], int(r["latency_us"]))
            for r in rows]


def approval_turnaround_pairs(tenant_id: str) -> list[tuple[str, str]]:
    """``(created_at, consumed_at)`` for the tenant's executed approvals."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT created_at, consumed_at FROM pending_approvals "
            "WHERE tenant_id = ? AND status = 'CONSUMED' AND consumed_at IS NOT NULL",
            (tenant_id,)).fetchall()
    finally:
        conn.close()
    return [(str(r["created_at"]), str(r["consumed_at"])) for r in rows]


def approval_status_counts(tenant_id: str) -> dict[str, int]:
    """Approval counts by status for one tenant."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM pending_approvals WHERE tenant_id = ? GROUP BY status",
            (tenant_id,)).fetchall()
    finally:
        conn.close()
    counts = {s: 0 for s in TERMINAL_STATUSES}
    counts.update({str(r["status"]): int(r["n"]) for r in rows})
    return counts
