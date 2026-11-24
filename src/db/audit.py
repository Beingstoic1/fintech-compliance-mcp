"""Append-only, HMAC-keyed, externally checkpointed audit ledger (T09).

What each layer buys (and what it does not):

* ``entry_hash = HMAC-SHA256(key[key_id], canonical_json(row incl. event_id, prev))``.
  Recomputing the chain needs the audit key, which never lives in the DB, so
  DB-write access alone cannot forge or re-chain rows (v1 used unkeyed SHA-256).
* ``BEFORE UPDATE/DELETE`` triggers abort every in-app mutation path. They do not
  stop someone who can drop triggers (raw file / DBA access); the HMAC does.
* Signed checkpoints ``{event_id, head, genesis}`` are written to an external
  append-only store after each commit. The chain alone cannot see the newest rows
  being cut off; the checkpoint can. ``FileCheckpointStore`` is the dev adapter. In
  production, implement ``CheckpointStore`` over WORM storage (e.g. S3 Object Lock,
  compliance mode) so the attacker cannot delete checkpoints either.
* ``detail`` is a structured code + allowlisted refs (``src.domain.ledger``), never
  free text, so PII, tokens and ``str(e)`` cannot be written into the ledger.

v1 rows (unkeyed) are preserved read-only in ``audit_logs_legacy_v1``; the v2 chain's
genesis is anchored to the v1 head (``LEGACY-V1:<hash>``).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from src.db.database import DB_PATH, get_connection
from src.domain.ledger import (
    DECISIONS,
    GENESIS,
    LEGACY_V1_PREFIX,
    MAX_DETAIL_CHARS,
    checkpoint_preimage,
    entry_preimage,
    normalize_detail,
)
from src.security.keys import Keyring

try:  # POSIX advisory locking for the dev checkpoint file
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)

_RING = Keyring.load(env="FINTECH_AUDIT_KEYS", active_env="FINTECH_AUDIT_ACTIVE_KID",
                     dev_file=".audit_keys", dev_prefix="audit-dev")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DECISION_SQL = ", ".join(f"'{d}'" for d in sorted(DECISIONS))

_AUDIT_DDL = f"""
CREATE TABLE IF NOT EXISTS audit_logs (
    event_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc  TEXT    NOT NULL,
    session_sub    TEXT    NOT NULL,
    actor_role     TEXT    NOT NULL,
    tenant_id      TEXT    NOT NULL,
    tool_name      TEXT    NOT NULL,
    args_digest    TEXT    NOT NULL,
    decision       TEXT    NOT NULL CHECK (decision IN ({_DECISION_SQL})),
    detail         TEXT    CHECK (detail IS NULL OR length(detail) <= {MAX_DETAIL_CHARS}),
    key_id         TEXT    NOT NULL,
    prev_hash      TEXT    NOT NULL,
    entry_hash     TEXT    NOT NULL
)
"""

_META_DDL = "CREATE TABLE IF NOT EXISTS audit_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)"

# table -> condition under which an INSERT would overwrite history. ``INSERT OR
# REPLACE`` deletes the conflicting row without firing DELETE triggers (SQLite runs
# them only with recursive_triggers on), so overwrites are refused up front. The
# legacy v1 archive is frozen outright.
_OVERWRITE_GUARD = {
    "audit_logs": "EXISTS (SELECT 1 FROM audit_logs WHERE event_id = NEW.event_id)",
    "audit_meta": "EXISTS (SELECT 1 FROM audit_meta WHERE k = NEW.k)",
    "audit_logs_legacy_v1": "1",
}
_APPEND_ONLY_TABLES = tuple(_OVERWRITE_GUARD)
_OPS = (("no_update", "UPDATE"), ("no_delete", "DELETE"), ("no_overwrite", "INSERT"))
TRIGGER_NAMES = tuple(f"trg_{t}_{op}" for t in _APPEND_ONLY_TABLES for op, _ in _OPS)


def install_triggers(conn: sqlite3.Connection) -> None:
    existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in _APPEND_ONLY_TABLES:
        if table not in existing:
            continue
        for op, verb in _OPS:
            when = f" WHEN {_OVERWRITE_GUARD[table]}" if verb == "INSERT" else ""
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_{op} BEFORE {verb} ON {table}{when} "
                f"BEGIN SELECT RAISE(ABORT, 'AUDIT_LOG_APPEND_ONLY'); END"
            )


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def init_audit_table() -> None:
    """Create the v2 ledger, archiving a v1 table if one is found. Idempotent."""
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        genesis = GENESIS
        if "args_sha256" in _columns(conn, "audit_logs"):  # v1 ledger: archive, never rewrite
            conn.execute("ALTER TABLE audit_logs RENAME TO audit_logs_legacy_v1")
            head = conn.execute(
                "SELECT entry_hash FROM audit_logs_legacy_v1 ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
            if head:
                genesis = LEGACY_V1_PREFIX + head[0]
        conn.execute(_AUDIT_DDL)
        conn.execute(_META_DDL)
        conn.execute("INSERT INTO audit_meta (k, v) SELECT 'genesis', ? "
                     "WHERE NOT EXISTS (SELECT 1 FROM audit_meta WHERE k = 'genesis')", (genesis,))
        install_triggers(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _genesis(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT v FROM audit_meta WHERE k='genesis'").fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def _preimage(row: Mapping[str, Any], decision: str | None = None) -> bytes:
    return entry_preimage(
        event_id=row["event_id"], prev_hash=row["prev_hash"], timestamp_utc=row["timestamp_utc"],
        session_sub=row["session_sub"], actor_role=row["actor_role"], tenant_id=row["tenant_id"],
        tool_name=row["tool_name"], args_digest=row["args_digest"],
        decision=decision if decision is not None else row["decision"],
        detail=row["detail"], key_id=row["key_id"],
    )


def _entry_hash(row: Mapping[str, Any], decision: str | None = None) -> str:
    return _RING.mac(row["key_id"], _preimage(row, decision))


# ---------------------------------------------------------------------------
# Checkpoints (external anchor against tail truncation)
# ---------------------------------------------------------------------------

class CheckpointStore(Protocol):
    """Append-only store outside the DB's trust boundary.

    Production: WORM object storage (S3 Object Lock in compliance mode, one object
    per checkpoint keyed by zero-padded event_id) written by a principal that cannot
    delete or overwrite objects.
    """

    def append(self, record: dict[str, Any]) -> None: ...

    def latest(self) -> dict[str, Any] | None: ...


class FileCheckpointStore:
    """Dev adapter: JSONL, one signed record per line, ``flock``-serialised."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def append(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "a", encoding="utf-8") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def latest(self) -> dict[str, Any] | None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                if fcntl:
                    fcntl.flock(fh, fcntl.LOCK_SH)
                lines = fh.readlines()
        except FileNotFoundError:
            return None
        best: dict[str, Any] | None = None
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and type(rec.get("event_id")) is int:
                if best is None or rec["event_id"] > best["event_id"]:
                    best = rec
        return best


_store: CheckpointStore = FileCheckpointStore(Path(
    os.environ.get("FINTECH_AUDIT_CHECKPOINT_PATH") or Path(DB_PATH).parent / "audit_checkpoints.jsonl"
))
_CHECKPOINT_EVERY = int(os.environ.get("FINTECH_AUDIT_CHECKPOINT_EVERY", "1"))


def get_checkpoint_store() -> CheckpointStore:
    return _store


def set_checkpoint_store(store: CheckpointStore) -> None:
    global _store
    _store = store


def _checkpoint_fields(rec: Mapping[str, Any]) -> dict[str, Any]:
    return {k: rec[k] for k in ("event_id", "head", "genesis", "ts", "key_id")}


def checkpoint() -> dict[str, Any] | None:
    """Sign the current head and append it to the external store."""
    conn = get_connection()
    try:
        head = conn.execute(
            "SELECT event_id, entry_hash FROM audit_logs ORDER BY event_id DESC LIMIT 1").fetchone()
        genesis = _genesis(conn)
    finally:
        conn.close()
    if head is None or genesis is None:
        return None
    kid = _RING.active_kid
    rec = {"event_id": head["event_id"], "head": head["entry_hash"], "genesis": genesis,
           "ts": datetime.now(UTC).isoformat(timespec="microseconds"), "key_id": kid}
    rec["sig"] = _RING.mac(kid, checkpoint_preimage(**rec))
    _store.append(rec)
    return rec


def maybe_checkpoint() -> None:
    """Call after a commit that appended audit rows. Never fails the caller: the
    business change is already committed, so a store outage is logged, not raised."""
    if _CHECKPOINT_EVERY <= 0:
        return
    try:
        conn = get_connection()
        try:
            row = conn.execute("SELECT MAX(event_id) FROM audit_logs").fetchone()
        finally:
            conn.close()
        if row[0] and row[0] % _CHECKPOINT_EVERY == 0:
            checkpoint()
    except Exception:  # noqa: BLE001
        _log.warning("audit checkpoint write failed", exc_info=False)


def _checkpoint_valid(rec: Mapping[str, Any]) -> bool:
    try:
        fields = _checkpoint_fields(rec)
    except KeyError:
        return False
    return _RING.verify(str(fields["key_id"]), checkpoint_preimage(**fields), rec.get("sig"))


# ---------------------------------------------------------------------------
# Append
# ---------------------------------------------------------------------------

def _append(conn: sqlite3.Connection, session_sub: str, actor_role: str, tenant_id: str,
            tool_name: str, args_digest: str, decision: str,
            detail: str | Mapping[str, Any] | None) -> int:
    if decision not in DECISIONS:
        raise ValueError("unknown audit decision")
    head = conn.execute(
        "SELECT event_id, entry_hash FROM audit_logs ORDER BY event_id DESC LIMIT 1").fetchone()
    if head:
        event_id, prev_hash = int(head["event_id"]) + 1, str(head["entry_hash"])
    else:
        genesis = _genesis(conn)
        if genesis is None:
            raise RuntimeError("audit ledger not initialised")
        event_id, prev_hash = 1, genesis
    row = {
        "event_id": event_id, "timestamp_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
        "session_sub": session_sub, "actor_role": actor_role, "tenant_id": tenant_id,
        "tool_name": tool_name, "args_digest": args_digest, "decision": decision,
        "detail": normalize_detail(detail), "key_id": _RING.active_kid, "prev_hash": prev_hash,
    }
    row["entry_hash"] = _entry_hash(row)
    conn.execute(
        f"INSERT INTO audit_logs ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
        tuple(row.values()),
    )
    return event_id


def log_event(
    session_sub: str,
    actor_role: str,
    tenant_id: str,
    tool_name: str,
    args_digest: str,
    decision: str,
    detail: str | Mapping[str, Any] | None = None,
    conn: sqlite3.Connection | None = None,
) -> int:
    """
    Append an audit row and return its event_id.

    ``detail`` is a code (``"NOT_FOUND"``) or ``{"code": ..., <allowlisted refs>}``;
    anything else is stored as ``INVALID_DETAIL``.

    With ``conn`` the row joins the caller's open ``BEGIN IMMEDIATE`` transaction and
    the caller must call ``maybe_checkpoint()`` after committing. Without it, the
    append runs (and is checkpointed) in its own transaction.
    """
    if conn is not None:
        return _append(conn, session_sub, actor_role, tenant_id, tool_name,
                       args_digest, decision, detail)
    own = get_connection()
    try:
        own.execute("BEGIN IMMEDIATE")
        event_id = _append(own, session_sub, actor_role, tenant_id, tool_name,
                           args_digest, decision, detail)
        own.commit()
    except Exception:
        own.rollback()
        raise
    finally:
        own.close()
    maybe_checkpoint()
    return event_id


# ---------------------------------------------------------------------------
# Read / verify
# ---------------------------------------------------------------------------

def get_audit_log(limit: int = 200) -> list[dict[str, Any]]:
    """Return up to *limit* rows from audit_logs, most recent first."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY event_id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _fail(event_id: int | None, reason: str, message: str, checked: int) -> dict[str, Any]:
    return {"ok": False, "corrupted_event_id": event_id, "reason": reason,
            "message": message, "checked": checked}


def verify_audit_chain(store: CheckpointStore | None = None) -> dict[str, Any]:
    """
    Stream the ledger in event_id order and verify, per row: consecutive ids from 1,
    ``prev_hash`` linkage (row 1 links to the stored genesis), a known ``key_id`` and
    the entry HMAC. Then check the latest external checkpoint: its signature, its
    genesis, that the ledger still reaches its event_id (tail truncation), and that
    the head there is the one that was signed.

    Returns ``{"ok": True, "checked": n, "checkpoint_event_id": id|None}`` or
    ``{"ok": False, "corrupted_event_id", "reason": <CODE>, "message", "checked"}``.
    """
    cp = (store or _store).latest()
    cp_id = cp.get("event_id") if cp else None
    conn = get_connection()
    try:
        genesis = _genesis(conn)
        expected_prev, expected_id, head_at_cp = genesis, 1, None
        for r in conn.execute("SELECT * FROM audit_logs ORDER BY event_id ASC"):
            row, eid, checked = dict(r), r["event_id"], expected_id - 1
            if genesis is None:
                return _fail(eid, "GENESIS_MISSING", "audit_meta genesis anchor is missing", checked)
            if eid != expected_id:
                return _fail(eid, "EVENT_ID_GAP",
                             f"expected event_id {expected_id}, found {eid} (row deletion)", checked)
            if row["prev_hash"] != expected_prev:
                return _fail(eid, "PREV_HASH_MISMATCH", "prev_hash does not link to the previous row",
                             checked)
            if not _RING.has(row["key_id"]):
                return _fail(eid, "UNKNOWN_KEY_ID", "row signed with a key not in the keyring", checked)
            if not _RING.verify(row["key_id"], _preimage(row), row["entry_hash"]):
                return _fail(eid, "ENTRY_HMAC_MISMATCH", "row contents do not match its HMAC", checked)
            if eid == cp_id:
                head_at_cp = row["entry_hash"]
            expected_prev, expected_id = row["entry_hash"], expected_id + 1
    finally:
        conn.close()

    checked = expected_id - 1
    if cp is not None:
        if not _checkpoint_valid(cp):
            return _fail(cp_id if isinstance(cp_id, int) else None, "CHECKPOINT_FORGED",
                         "latest external checkpoint has an invalid signature", checked)
        if cp["genesis"] != genesis:
            return _fail(None, "GENESIS_MISMATCH", "ledger genesis differs from the checkpoint", checked)
        if checked < cp["event_id"]:  # latest() only yields int event_ids
            return _fail(checked + 1, "TRUNCATION_DETECTED",
                         f"ledger ends at event_id {checked} but a checkpoint covers {cp_id}", checked)
        if head_at_cp != cp["head"]:
            return _fail(cp_id, "CHECKPOINT_HEAD_MISMATCH",
                         "head at the checkpointed event_id differs from the signed head", checked)
    return {"ok": True, "checked": checked, "checkpoint_event_id": cp_id}


# ---------------------------------------------------------------------------
# Module init
# ---------------------------------------------------------------------------
init_audit_table()
