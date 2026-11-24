"""Tamper lab: simulates an attacker with raw DB-file access (demo + tests only).

The ledger's triggers make every in-app UPDATE/DELETE abort, so each attack here
does what a real attacker with file access would: drop the triggers, mutate, and
recreate them. The point is to show that the HMAC chain and the external
checkpoint still catch it. Disabled when ``FINTECH_ENV=production``.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from src.db import audit
from src.db.database import get_connection
from src.domain.ledger import DECISIONS

_TAMPERABLE_FIELDS = frozenset({"decision", "tenant_id", "detail", "session_sub", "actor_role"})


def enabled() -> bool:
    return os.environ.get("FINTECH_ENV", "").lower() != "production"


def _require_enabled() -> None:
    if not enabled():
        raise PermissionError("tamper lab is disabled when FINTECH_ENV=production")


@contextmanager
def _raw_access() -> Iterator[sqlite3.Connection]:
    _require_enabled()
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for name in audit.TRIGGER_NAMES:
            conn.execute(f"DROP TRIGGER IF EXISTS {name}")
        yield conn
        audit.install_triggers(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def tamper_row(event_id: int, new_decision: str) -> None:
    """Rewrite one row's decision without (being able to) recompute its HMAC."""
    tamper_field(event_id, "decision", new_decision)


def tamper_field(event_id: int, field: str, value: str | None) -> None:
    if field not in _TAMPERABLE_FIELDS:
        raise ValueError("field not tamperable in the lab")
    with _raw_access() as conn:
        conn.execute(f"UPDATE audit_logs SET {field}=? WHERE event_id=?", (value, event_id))


def delete_row(event_id: int) -> None:
    with _raw_access() as conn:
        conn.execute("DELETE FROM audit_logs WHERE event_id=?", (event_id,))


def truncate_tail(n: int) -> None:
    """Delete the newest ``n`` rows and rewind the sequence: invisible to the chain
    alone, caught by the external checkpoint."""
    with _raw_access() as conn:
        max_id = conn.execute("SELECT COALESCE(MAX(event_id), 0) FROM audit_logs").fetchone()[0]
        conn.execute("DELETE FROM audit_logs WHERE event_id > ?", (max_id - n,))
        conn.execute("UPDATE sqlite_sequence SET seq=? WHERE name='audit_logs'", (max(max_id - n, 0),))


def restore_row(event_id: int) -> bool:
    """Undo a lab ``tamper_row`` by finding the decision whose HMAC matches the stored
    ``entry_hash`` (possible here only because the lab holds the audit key)."""
    _require_enabled()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM audit_logs WHERE event_id=?", (event_id,)).fetchone()
    finally:
        conn.close()
    if row is None or not audit._RING.has(row["key_id"]):
        return False
    for decision in sorted(DECISIONS):
        if audit._entry_hash(dict(row), decision) == row["entry_hash"]:
            with _raw_access() as c:
                c.execute("UPDATE audit_logs SET decision=? WHERE event_id=?", (decision, event_id))
            return True
    return False


def reset_ledger_for_tests() -> None:
    """Privileged wipe for test isolation: rows, sequence, and the dev checkpoint file."""
    store = audit.get_checkpoint_store()
    if not isinstance(store, audit.FileCheckpointStore):
        raise RuntimeError("reset only supported for the dev file checkpoint store")
    with _raw_access() as conn:
        conn.execute("DELETE FROM audit_logs")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_logs'")
    store.path.unlink(missing_ok=True)
