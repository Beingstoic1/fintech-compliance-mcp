"""Adversarial T18–T19: append-only enforcement and forgery of the HMAC audit chain.

Extends (does not repeat) Tests 12–14 in tests/test_security_and_mcp.py, which cover a
single-row decision tamper, a middle-row delete, `truncate_tail`, and tenant/detail
tampering. Here: every-column UPDATE, REPLACE-based overwrite, the legacy v1 archive,
re-chaining with an attacker key, forged checkpoints, and a full table wipe.

Three-way assertion per attack: (1) the abort / verifier verdict, (2) the ledger
rows are what they were (or the verifier pinpoints the damage), (3) the audit trail.
"""
import hashlib
import hmac
import sqlite3

import pytest

from src.db import audit, database
from src.db.audit import FileCheckpointStore, log_event, verify_audit_chain
from src.db.database import get_connection
from src.demo import tamper_lab
from src.domain.ledger import GENESIS, LEGACY_V1_PREFIX, checkpoint_preimage, entry_preimage

ATTACKER_KEY = b"attacker-controlled-audit-key-0123456789abcdef"
_COLUMNS = ("event_id", "timestamp_utc", "session_sub", "actor_role", "tenant_id", "tool_name",
            "args_digest", "decision", "detail", "key_id", "prev_hash", "entry_hash")


def _seed(n: int = 3) -> None:
    for i in range(n):
        log_event("ledger_attacker_test", "senior_investigator", "tenant_neobank_in",
                  "query_transactions", f"digest_{i}", "BLOCK" if i == 1 else "ALLOW", "NOT_FOUND")


def _rows(table: str) -> list[dict]:
    conn = get_connection()
    try:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY event_id")]
    finally:
        conn.close()


def _ledger() -> list[dict]:
    return _rows("audit_logs")


def _must_abort(sql: str, params: tuple = ()) -> None:
    conn = get_connection()
    try:
        with pytest.raises(sqlite3.IntegrityError, match="AUDIT_LOG_APPEND_ONLY"):
            conn.execute(sql, params)
    finally:
        conn.close()


def _preimage(row: dict) -> bytes:
    return entry_preimage(event_id=row["event_id"], prev_hash=row["prev_hash"],
                          timestamp_utc=row["timestamp_utc"], session_sub=row["session_sub"],
                          actor_role=row["actor_role"], tenant_id=row["tenant_id"],
                          tool_name=row["tool_name"], args_digest=row["args_digest"],
                          decision=row["decision"], detail=row["detail"], key_id=row["key_id"])


def _rechain(start: int, *, kid: str | None, mac) -> None:
    """Attacker with raw file access + the (public) algorithm: flip row `start` from
    BLOCK to ALLOW, then recompute every hash and link from there to the head."""
    with tamper_lab._raw_access() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM audit_logs ORDER BY event_id")]
        prev = rows[start - 2]["entry_hash"]
        for row in rows[start - 1:]:
            if row["event_id"] == start:
                row["decision"] = "ALLOW"
            row["key_id"] = kid or row["key_id"]
            row["prev_hash"] = prev
            row["entry_hash"] = mac(_preimage(row))
            conn.execute("UPDATE audit_logs SET decision=?, key_id=?, prev_hash=?, entry_hash=? "
                         "WHERE event_id=?", (row["decision"], row["key_id"], row["prev_hash"],
                                              row["entry_hash"], row["event_id"]))
            prev = row["entry_hash"]


# ─── T18: append-only enforcement ────────────────────────────────────────────

def test_t18_every_column_update_and_any_delete_abort():
    _seed()
    before = _ledger()
    for col in _COLUMNS:
        value = 999 if col == "event_id" else "TAMPERED"
        _must_abort(f"UPDATE audit_logs SET {col}=? WHERE event_id=2", (value,))
    _must_abort("DELETE FROM audit_logs")
    _must_abort("DELETE FROM audit_logs WHERE event_id=3")
    _must_abort("DELETE FROM audit_meta")
    _must_abort("UPDATE audit_meta SET v='GENESIS2' WHERE k='genesis'")
    # (2) nothing changed; (3) the chain and checkpoint still verify end to end
    assert _ledger() == before
    assert verify_audit_chain() == {"ok": True, "checked": 3, "checkpoint_event_id": 3}


def test_t18_insert_or_replace_cannot_overwrite_history():
    """REPLACE deletes the conflicting row without firing DELETE triggers; the
    INSERT-side guard has to refuse it."""
    _seed()
    before = _ledger()
    forged = {**before[1], "decision": "ALLOW"}
    cols = ", ".join(forged)
    for verb in ("INSERT OR REPLACE", "REPLACE"):
        _must_abort(f"{verb} INTO audit_logs ({cols}) VALUES ({', '.join('?' * len(forged))})",
                    tuple(forged.values()))
    _must_abort("INSERT OR REPLACE INTO audit_meta (k, v) VALUES ('genesis', 'ATTACKER-GENESIS')")
    # (2)/(3) rows and genesis untouched; still verifies
    assert _ledger() == before
    conn = get_connection()
    try:
        assert conn.execute("SELECT v FROM audit_meta WHERE k='genesis'").fetchone()[0] == GENESIS
    finally:
        conn.close()
    assert verify_audit_chain()["ok"] is True
    # A genuine append still works (the guard is not over-broad)
    assert log_event("ledger_attacker_test", "junior_analyst", "tenant_neobank_in",
                     "query_transactions", "digest_after", "ALLOW") == 4


def test_t18_legacy_v1_archive_is_read_only_after_migration(tmp_path, monkeypatch):
    """Run the real v1 -> v2 migration on a throwaway DB, then attack the archive."""
    db = tmp_path / "legacy.db"
    monkeypatch.setattr(database, "DB_PATH", db)
    monkeypatch.setattr(audit, "_store", FileCheckpointStore(tmp_path / "cp.jsonl"))
    conn = get_connection()
    conn.execute("""CREATE TABLE audit_logs (event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_utc TEXT, session_sub TEXT, actor_role TEXT, tenant_id TEXT, tool_name TEXT,
        args_sha256 TEXT, decision TEXT, detail TEXT, prev_hash TEXT, entry_hash TEXT)""")
    for i, (prev, head) in enumerate((("GENESIS", "v1hash1"), ("v1hash1", "v1head"))):
        conn.execute("INSERT INTO audit_logs (timestamp_utc, session_sub, actor_role, tenant_id,"
                     " tool_name, args_sha256, decision, detail, prev_hash, entry_hash) VALUES "
                     "(?, 'old', 'junior_analyst', 'tenant_neobank_in', 'get_account_profile',"
                     " 'x', 'ALLOW', '', ?, ?)", (f"2026-01-0{i + 1}", prev, head))
    conn.commit()
    conn.close()

    audit.init_audit_table()
    audit.init_audit_table()  # idempotent re-init must not trip the genesis guard
    eid = log_event("new", "junior_analyst", "tenant_neobank_in", "get_account_profile", "d", "ALLOW")
    legacy_before = _rows("audit_logs_legacy_v1")

    # (1) the archive refuses UPDATE / DELETE / INSERT / REPLACE
    _must_abort("UPDATE audit_logs_legacy_v1 SET decision='BLOCK' WHERE event_id=1")
    _must_abort("DELETE FROM audit_logs_legacy_v1")
    _must_abort("INSERT INTO audit_logs_legacy_v1 (decision) VALUES ('ALLOW')")
    _must_abort("INSERT OR REPLACE INTO audit_logs_legacy_v1 (event_id, decision) VALUES (2, 'BLOCK')")
    # (2) archive unchanged, v2 anchored to the v1 head
    assert _rows("audit_logs_legacy_v1") == legacy_before
    assert len(legacy_before) == 2
    assert _ledger()[0]["prev_hash"] == LEGACY_V1_PREFIX + "v1head" and eid == 1
    # (3) the v2 chain over it verifies
    assert verify_audit_chain()["ok"] is True


# ─── T19: forging the chain / checkpoints ────────────────────────────────────

@pytest.mark.parametrize("variant", ["attacker_key_real_kid", "attacker_own_kid", "unkeyed_sha256"])
def test_t19_rechaining_without_the_audit_key_is_detected(variant):
    _seed()
    before = _ledger()
    assert before[1]["decision"] == "BLOCK"
    if variant == "unkeyed_sha256":
        _rechain(2, kid=None, mac=lambda b: hashlib.sha256(b).hexdigest())
    else:
        kid = "attacker-k1" if variant == "attacker_own_kid" else None
        _rechain(2, kid=kid, mac=lambda b: hmac.new(ATTACKER_KEY, b, hashlib.sha256).hexdigest())

    after = _ledger()
    # the forgery is internally consistent: every link matches the previous hash
    assert all(after[i]["prev_hash"] == after[i - 1]["entry_hash"] for i in range(1, len(after)))
    # (1) yet the verifier names the first forged row
    res = verify_audit_chain()
    expected = "UNKNOWN_KEY_ID" if variant == "attacker_own_kid" else "ENTRY_HMAC_MISMATCH"
    assert (res["ok"], res["reason"], res["corrupted_event_id"], res["checked"]) == (False, expected, 2, 1)
    # (2) row 1 was not touched; (3) the forged decision is the one being flagged
    assert after[0] == before[0] and after[1]["decision"] == "ALLOW"


@pytest.mark.parametrize("variant", ["garbage_sig", "attacker_key_real_kid", "attacker_own_kid"])
def test_t19_forged_checkpoint_line_is_rejected(variant):
    _seed()
    before = _ledger()
    store = audit.get_checkpoint_store()
    assert isinstance(store, FileCheckpointStore)
    # A truncation-hiding forgery: claim a head far past the real one
    rec = {"event_id": 99, "head": "f" * 64, "genesis": GENESIS, "ts": "2026-11-24T00:00:00.000000+00:00",
           "key_id": "attacker-k1" if variant == "attacker_own_kid" else audit._RING.active_kid}
    rec["sig"] = "0" * 64 if variant == "garbage_sig" else hmac.new(
        ATTACKER_KEY, checkpoint_preimage(**rec), hashlib.sha256).hexdigest()
    store.append(rec)

    # (1) the forged line is the latest and is refused
    res = verify_audit_chain()
    assert (res["ok"], res["reason"], res["corrupted_event_id"]) == (False, "CHECKPOINT_FORGED", 99)
    # (2) the ledger rows themselves still chain (checked == 3); (3) untouched
    assert res["checked"] == 3 and _ledger() == before
    # junk lines are ignored rather than trusted
    with open(store.path, "a", encoding="utf-8") as fh:
        fh.write('not json\n{"event_id": "1000", "head": "x"}\n')
    assert verify_audit_chain()["reason"] == "CHECKPOINT_FORGED"


def test_t19_full_table_wipe_with_existing_checkpoint_is_detected():
    _seed(4)
    head = _ledger()[-1]
    with tamper_lab._raw_access() as conn:  # raw-file attacker wipes everything
        conn.execute("DELETE FROM audit_logs")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_logs'")
    assert _ledger() == []

    # (1) an empty ledger is not "trivially valid"
    res = verify_audit_chain()
    assert (res["ok"], res["reason"], res["corrupted_event_id"], res["checked"]) == (
        False, "TRUNCATION_DETECTED", 1, 0)
    # (2) business keeps writing after the wipe: a fresh row 1 still sits short of the checkpoint
    log_event("post_wipe", "junior_analyst", "tenant_neobank_in", "query_transactions", "d", "ALLOW")
    res = verify_audit_chain()
    assert (res["reason"], res["checked"]) == ("TRUNCATION_DETECTED", 1)
    # (3) the signed checkpoint still names the wiped head
    cp = audit.get_checkpoint_store().latest()
    assert (cp["event_id"], cp["head"]) == (4, head["entry_hash"])

    # Re-anchoring the genesis as well is caught against the checkpoint's genesis
    with tamper_lab._raw_access() as conn:
        conn.execute("DELETE FROM audit_logs")
        conn.execute("UPDATE audit_meta SET v='ATTACKER-GENESIS' WHERE k='genesis'")
    assert verify_audit_chain()["reason"] == "GENESIS_MISMATCH"
    with tamper_lab._raw_access() as conn:  # restore for the isolation fixture
        conn.execute("UPDATE audit_meta SET v=? WHERE k='genesis'", (GENESIS,))

