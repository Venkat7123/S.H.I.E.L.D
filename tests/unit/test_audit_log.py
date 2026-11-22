"""The audit log: append-only, hash-chained, sanitised."""

from __future__ import annotations

import sqlite3

import pytest

from core.audit_log import AuditLog, demo_tamper_entry, sanitize
from core.canonical import ZERO_HASH
from core.models import EventType


@pytest.fixture
def log(tmp_path):
    lg = AuditLog(tmp_path / "audit.db", tmp_path / "audit.jsonl")
    yield lg
    lg.close()


def _fill(log, n=6):
    for i in range(n):
        log.append(
            EventType.TOOL_CALL,
            "transaction_analyst",
            {"case_id": "CASE-001", "seq": i},
            "p" * 64,
        )


def test_the_chain_starts_from_zero_and_links(log) -> None:
    _fill(log, 3)
    entries = log.entries()
    assert entries[0].prev_hash == ZERO_HASH
    for prev, curr in zip(entries, entries[1:]):
        assert curr.prev_hash == prev.entry_hash
    assert log.verify_chain().ok


def test_update_is_refused_by_the_database(log) -> None:
    _fill(log, 2)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        log.conn.execute("UPDATE audit_log SET actor = 'attacker' WHERE idx = 0")


def test_delete_is_refused_by_the_database(log) -> None:
    _fill(log, 2)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        log.conn.execute("DELETE FROM audit_log WHERE idx = 0")


def test_editing_an_entry_is_detected_at_that_index(tmp_path) -> None:
    db = tmp_path / "audit.db"
    log = AuditLog(db, tmp_path / "audit.jsonl")
    _fill(log, 10)
    assert log.verify_chain().ok
    log.close()

    demo_tamper_entry(db, 7)

    log2 = AuditLog(db, tmp_path / "audit.jsonl")
    result = log2.verify_chain()
    assert not result.ok
    assert result.first_broken_index == 7
    log2.close()


def test_tampering_with_the_payload_is_also_detected(tmp_path) -> None:
    db = tmp_path / "audit.db"
    log = AuditLog(db, tmp_path / "audit.jsonl")
    _fill(log, 5)
    log.close()
    demo_tamper_entry(db, 2, field="payload", new_value='{"case_id":"CASE-999"}')
    log2 = AuditLog(db, tmp_path / "audit.jsonl")
    assert log2.verify_chain().first_broken_index == 2
    log2.close()


def test_holder_names_and_long_digit_runs_are_masked() -> None:
    clean = sanitize(
        {
            "holder_name": "Rohan Mehta",
            "note": "card 4539123412341234 and account 987654321",
            "amount": 95000,
            "nested": [{"name": "Priya Nair"}],
        }
    )
    assert clean["holder_name"] == "R***"
    assert "4539123412341234" not in clean["note"]
    assert "987654321" not in clean["note"]
    assert clean["amount"] == 95000  # amounts stay readable
    assert clean["nested"][0]["name"] == "P***"


def test_hashes_survive_sanitisation_intact() -> None:
    """Masking must not eat the identifiers that make the log usable.

    About 60% of SHA-256 digests contain a run of seven or more digits, so a
    naive digit mask corrupts most of them - and with them the ability to look
    up raw output by hash or match an action to its approval.
    """
    import hashlib

    digests = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(200)]
    for digest in digests:
        assert sanitize({"raw_hash": digest})["raw_hash"] == digest
        assert sanitize({"action_hash": digest})["action_hash"] == digest
        # Also when the key is not on the allowlist, by shape alone.
        assert sanitize({"some_other_field": digest})["some_other_field"] == digest
    assert sanitize({"evidence_raw_hashes": digests})["evidence_raw_hashes"] == digests


def test_a_long_digit_run_that_is_not_a_hash_is_still_masked() -> None:
    assert "<redacted:" in sanitize({"note": "account 123456789012345"})["note"]
    # A 32-char all-digit string has no hex letters, so it is not taken for a hash.
    assert "<redacted:" in sanitize({"x": "1" * 32})["x"]


def test_sanitisation_happens_before_hashing(log) -> None:
    """What is hashed is what is stored - no window where raw data exists."""
    entry = log.append(
        EventType.TOOL_RESULT, "worker", {"holder_name": "Rohan Mehta"}, "p" * 64
    )
    assert entry.payload["holder_name"] == "R***"
    assert entry.expected_hash() == entry.entry_hash


def test_the_jsonl_mirror_matches_the_database(log, tmp_path) -> None:
    from core.audit_log import iter_jsonl

    _fill(log, 4)
    mirrored = list(iter_jsonl(tmp_path / "audit.jsonl"))
    assert len(mirrored) == log.count()
    assert [m["entry_hash"] for m in mirrored] == [e.entry_hash for e in log.entries()]


def test_entries_can_be_filtered_by_case_and_type(log) -> None:
    _fill(log, 3)
    log.append(EventType.DENIAL, "worker", {"case_id": "CASE-002"}, "p" * 64)
    assert len(log.by_case("CASE-001")) == 3
    assert len(log.by_type(EventType.DENIAL)) == 1
