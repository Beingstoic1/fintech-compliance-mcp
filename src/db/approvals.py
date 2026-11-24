"""Four-Eyes approval storage (T07).

The state graph from ``src.domain.approvals`` is enforced in SQL too:
  * ``status`` CHECK constraint; ``tenant_id NOT NULL``; approver != requester CHECK;
  * ``UNIQUE(tenant_id, requester_sub, idempotency_key)`` for idempotent staging;
  * triggers abort any UPDATE that is not a legal transition, touches an immutable
    column, or modifies a terminal row.
All mutating helpers take the caller's connection so a transition, the business
action, and its audit row commit (or roll back) together.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Iterable

_COLUMNS_DDL = """
    approval_id               TEXT PRIMARY KEY,
    tenant_id                 TEXT NOT NULL,
    requester_sub             TEXT NOT NULL,
    requester_role            TEXT NOT NULL,
    tool_name                 TEXT NOT NULL,
    canonical_args_json       TEXT NOT NULL,
    key_id                    TEXT NOT NULL,
    args_digest               TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','APPROVED','CONSUMED','REJECTED','EXPIRED')),
    idempotency_key           TEXT,
    created_at                TEXT NOT NULL,
    expires_at                TEXT NOT NULL,
    approver_sub              TEXT,
    approved_at               TEXT,
    approved_amr              TEXT,
    rejected_by_sub           TEXT,
    rejected_at               TEXT,
    rejection_reason          TEXT,
    executed_by_sub           TEXT,
    consumed_at               TEXT,
    execution_idempotency_key TEXT,
    execution_result_json     TEXT,
    CHECK (approver_sub IS NULL OR approver_sub <> requester_sub),
    UNIQUE (tenant_id, requester_sub, idempotency_key)
"""

_IMMUTABLE = ("approval_id", "tenant_id", "requester_sub", "requester_role", "tool_name",
              "canonical_args_json", "key_id", "args_digest", "idempotency_key",
              "created_at", "expires_at")

_TRIGGERS = f"""
CREATE TRIGGER IF NOT EXISTS trg_pending_approvals_transition
BEFORE UPDATE ON pending_approvals
WHEN NOT (
       (OLD.status = 'PENDING'  AND NEW.status IN ('APPROVED','REJECTED','EXPIRED'))
    OR (OLD.status = 'APPROVED' AND NEW.status IN ('CONSUMED','REJECTED','EXPIRED'))
)
BEGIN
    SELECT RAISE(ABORT, 'ILLEGAL_APPROVAL_TRANSITION');
END;

CREATE TRIGGER IF NOT EXISTS trg_pending_approvals_immutable
BEFORE UPDATE ON pending_approvals
WHEN {" OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in _IMMUTABLE)}
BEGIN
    SELECT RAISE(ABORT, 'APPROVAL_ROW_IMMUTABLE');
END;

CREATE INDEX IF NOT EXISTS idx_pending_approvals_tenant_status
    ON pending_approvals (tenant_id, status, expires_at);
"""

# Columns a transition may set, in addition to status.
_SETTABLE = frozenset({"approver_sub", "approved_at", "approved_amr", "rejected_by_sub",
                       "rejected_at", "rejection_reason", "executed_by_sub", "consumed_at",
                       "execution_idempotency_key", "execution_result_json"})


def init_schema(conn: sqlite3.Connection) -> None:
    """Create the table, migrating the pre-T07 layout in place if present."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='pending_approvals'"
    ).fetchone()
    if row is not None and "args_digest" not in row[0]:
        _migrate_legacy(conn)
    conn.execute(f"CREATE TABLE IF NOT EXISTS pending_approvals ({_COLUMNS_DDL})")
    conn.executescript(_TRIGGERS)


def _migrate_legacy(conn: sqlite3.Connection) -> None:
    """Copy old rows across. Legacy bindings were unkeyed, so they get
    key_id='legacy-unkeyed' and can never verify (fail closed); rows with a NULL
    tenant are orphaned and, if still open, rejected."""
    conn.execute("ALTER TABLE pending_approvals RENAME TO pending_approvals_legacy")
    conn.execute(f"CREATE TABLE pending_approvals ({_COLUMNS_DDL})")
    conn.execute("""
        INSERT OR IGNORE INTO pending_approvals
            (approval_id, tenant_id, requester_sub, requester_role, tool_name,
             canonical_args_json, key_id, args_digest, status, created_at, expires_at,
             executed_by_sub, consumed_at)
        SELECT approval_id, COALESCE(tenant_id, '__orphaned__'), requester_sub, requester_role,
               tool_name, canonical_args_json, 'legacy-unkeyed', args_sha256,
               CASE WHEN tenant_id IS NULL AND status IN ('PENDING','APPROVED') THEN 'REJECTED'
                    WHEN status IN ('PENDING','APPROVED','CONSUMED','REJECTED','EXPIRED') THEN status
                    ELSE 'REJECTED' END,
               created_at, expires_at,
               CASE WHEN status = 'CONSUMED' THEN approver_sub END, consumed_at
        FROM pending_approvals_legacy
    """)
    conn.execute("DROP TABLE pending_approvals_legacy")


# ─── reads ──────────────────────────────────────────────────────────────────

def get(conn: sqlite3.Connection, approval_id: str, tenant_id: str) -> dict | None:
    """Tenant-scoped (T10): another tenant's approval is indistinguishable from a
    missing one, matching what Postgres RLS returns."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    row = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=? AND tenant_id=?",
                       (approval_id, tenant_id)).fetchone()
    return dict(row) if row else None


def find_by_idempotency(conn: sqlite3.Connection, tenant_id: str, requester_sub: str,
                        idempotency_key: str) -> dict | None:
    row = conn.execute(
        """SELECT * FROM pending_approvals
           WHERE tenant_id=? AND requester_sub=? AND idempotency_key=?""",
        (tenant_id, requester_sub, idempotency_key),
    ).fetchone()
    return dict(row) if row else None


def list_for_tenant(conn: sqlite3.Connection, tenant_id: str,
                    statuses: Iterable[str] = ("PENDING", "APPROVED")) -> list[dict]:
    statuses = tuple(statuses)
    ph = ",".join("?" for _ in statuses)
    rows = conn.execute(
        f"SELECT * FROM pending_approvals WHERE tenant_id=? AND status IN ({ph}) ORDER BY created_at DESC",
        (tenant_id, *statuses),
    ).fetchall()
    return [dict(r) for r in rows]


# ─── writes (caller owns the transaction) ────────────────────────────────────

def insert(conn: sqlite3.Connection, *, approval_id: str, tenant_id: str, requester_sub: str,
           requester_role: str, tool_name: str, canonical_args_json: str, key_id: str,
           args_digest: str, created_at: str, expires_at: str,
           idempotency_key: str | None = None) -> None:
    conn.execute(
        """INSERT INTO pending_approvals
           (approval_id, tenant_id, requester_sub, requester_role, tool_name,
            canonical_args_json, key_id, args_digest, status, idempotency_key,
            created_at, expires_at)
           VALUES (?,?,?,?,?,?,?,?,'PENDING',?,?,?)""",
        (approval_id, tenant_id, requester_sub, requester_role, tool_name,
         canonical_args_json, key_id, args_digest, idempotency_key, created_at, expires_at),
    )


def transition(conn: sqlite3.Connection, approval_id: str, tenant_id: str,
               from_statuses: Iterable[str], to_status: str, *,
               unexpired_at: str | None = None, **fields: Any) -> bool:
    """Compare-and-set a status change. True iff exactly one row moved."""
    bad = set(fields) - _SETTABLE
    if bad:
        raise ValueError(f"non-settable columns: {sorted(bad)}")
    from_statuses = tuple(from_statuses)
    sets = ", ".join(["status=?"] + [f"{c}=?" for c in fields])
    sql = (f"UPDATE pending_approvals SET {sets} WHERE approval_id=? AND tenant_id=? "
           f"AND status IN ({','.join('?' for _ in from_statuses)})")
    params: list[Any] = [to_status, *fields.values(), approval_id, tenant_id, *from_statuses]
    if unexpired_at is not None:
        sql += " AND expires_at > ?"
        params.append(unexpired_at)
    return conn.execute(sql, params).rowcount == 1


def expire_stale(conn: sqlite3.Connection, tenant_id: str, now_iso: str) -> int:
    return conn.execute(
        """UPDATE pending_approvals SET status='EXPIRED'
           WHERE tenant_id=? AND status IN ('PENDING','APPROVED') AND expires_at <= ?""",
        (tenant_id, now_iso),
    ).rowcount
