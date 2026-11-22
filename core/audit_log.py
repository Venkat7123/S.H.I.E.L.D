"""Append-only, hash-chained audit log.

Three properties the rest of the system depends on:

1. **Write-before-act.** Every consequential step logs its *intent* first. If
   the log write fails the step does not run. A missing action is recoverable;
   an unrecorded action is not.
2. **Tamper-evident.** Each entry hashes its own contents plus the previous
   entry's hash. Editing entry *n* breaks every hash from *n* onward, and
   :func:`AuditLog.verify_chain` reports the first broken index.
3. **Append-only in storage, not just in convention.** SQLite triggers abort
   ``UPDATE`` and ``DELETE`` on the table. There is no update path in this
   module's API.

What this does *not* do: detect someone with full machine access rewriting the
whole log or truncating its tail. That needs checkpoints held off the machine -
see ``docs/limitations.md``.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict

from core.canonical import ZERO_HASH, canonical_json, hash_obj
from core.db import DEFAULT_DB, connect
from core.models import EventType, utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    idx         INTEGER PRIMARY KEY,
    entry_id    TEXT    NOT NULL UNIQUE,
    timestamp   TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    policy_hash TEXT    NOT NULL,
    prev_hash   TEXT    NOT NULL,
    entry_hash  TEXT    NOT NULL
);
"""

_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE refused');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE refused');
END;
"""

_TRIGGER_NAMES = ("audit_log_no_update", "audit_log_no_delete")

# A run of 7+ digits is an account number, a card number or a phone number.
# Shorter runs are amounts and dates, which the auditor needs to see.
_LONG_DIGITS = re.compile(r"\d{7,}")
_NAME_KEYS = frozenset({"holder_name", "holder", "name", "customer_name", "approver_name"})

# Hashes must survive sanitisation untouched. Roughly 60% of SHA-256 digests
# contain a run of seven or more digits somewhere, so without this the masking
# would quietly corrupt the very identifiers that make the log useful - you
# could no longer look up raw output by its raw_hash, or match an action to its
# approval. A hex digest is not personal data, so there is nothing to mask.
_HASH_KEYS = frozenset(
    {
        "raw_hash",
        "order_hash",
        "action_hash",
        "entry_hash",
        "prev_hash",
        "policy_hash",
        "payload_hash",
        "idempotency_key",
        "key",
        "evidence_raw_hashes",
    }
)

# Identifiers this system generates. Masking a digit run inside ``APPR-1234567…``
# or ``CALL-…`` breaks the cross-references the log exists to provide, and none
# of them is personal data. Listed explicitly rather than matched by shape, so
# adding a field that *does* carry personal data is a visible decision.
_ID_KEYS = frozenset(
    {
        "case_id",
        "call_id",
        "order_id",
        "proposal_id",
        "approval_id",
        "entry_id",
        "log_entry_id",
        "record_ids",
        "record_refs",
        "tool_log",
        "considered_txns",
        "supporting_claims",
        "account_id",
        "target",
        "target_account",
        "subject_account",
        "trigger_txn",
        "scenario",
    }
)
_NEVER_MASK = _HASH_KEYS | _ID_KEYS

_HEX_DIGEST = re.compile(r"^(?=.*[a-f])[0-9a-f]{32,}$")


class AuditWriteError(Exception):
    """The log could not be written. The caller must not perform the action."""


class AuditEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int
    entry_id: str
    timestamp: str
    event_type: EventType
    actor: str
    payload: dict[str, Any]
    policy_hash: str
    prev_hash: str
    entry_hash: str

    def hashed_payload(self) -> dict[str, Any]:
        d = self.model_dump(mode="json")
        d.pop("entry_hash")
        return d

    def expected_hash(self) -> str:
        return hash_obj(self.hashed_payload())


class ChainVerification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    entries: int
    first_broken_index: int | None = None
    detail: str = ""


# --------------------------------------------------------------------------
# Sanitisation
# --------------------------------------------------------------------------


def sanitize(value: Any, *, key: str | None = None) -> Any:
    """Mask personal data before it reaches the log, the UI or git.

    Raw tool output never comes here in the first place - the gateway stores it
    in the raw store and logs only its hash. This is the second line: it masks
    holder names and long digit runs wherever they turn up.
    """
    if isinstance(value, dict):
        return {k: sanitize(v, key=k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, key=key) for v in value]
    if isinstance(value, str):
        if key in _NAME_KEYS:
            return (value[:1] + "***") if value else ""
        if key in _NEVER_MASK or _HEX_DIGEST.match(value):
            return value
        return _LONG_DIGITS.sub(lambda m: f"<redacted:{len(m.group(0))}digits>", value)
    return value


# --------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------


class AuditLog:
    """Append-only hash chain over SQLite, mirrored to JSONL."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB,
        jsonl_path: str | Path = "logs/audit.jsonl",
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        self._owns_conn = conn is None
        self.conn = conn or connect(db_path)
        self.jsonl_path = Path(jsonl_path)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self.conn.executescript(_TRIGGERS)

    # -- writing -----------------------------------------------------------

    def append(
        self,
        event_type: EventType,
        actor: str,
        payload: dict[str, Any],
        policy_hash: str,
    ) -> AuditEntry:
        """Append one entry. Raises :class:`AuditWriteError` on any failure.

        Callers treat a raised error as "do not proceed". The gateway turns it
        into ``AUDIT_WRITE_FAILED`` and denies the call.
        """
        with self._lock:
            try:
                return self._append_locked(event_type, actor, payload, policy_hash)
            except AuditWriteError:
                raise
            except Exception as exc:
                raise AuditWriteError(f"audit append failed: {exc}") from exc

    def _append_locked(
        self,
        event_type: EventType,
        actor: str,
        payload: dict[str, Any],
        policy_hash: str,
    ) -> AuditEntry:
        row = self.conn.execute(
            "SELECT idx, entry_hash FROM audit_log ORDER BY idx DESC LIMIT 1"
        ).fetchone()
        index = (row["idx"] + 1) if row else 0
        prev_hash = row["entry_hash"] if row else ZERO_HASH

        clean = sanitize(payload)
        # Round-trip through canonical JSON so what we hash is exactly what we
        # store, with no surprises from unserialisable objects at write time.
        clean = json.loads(canonical_json(clean))

        draft = {
            "index": index,
            "entry_id": f"LOG-{index:06d}",
            "timestamp": utcnow().isoformat(),
            "event_type": EventType(event_type).value,
            "actor": actor,
            "payload": clean,
            "policy_hash": policy_hash,
            "prev_hash": prev_hash,
        }
        entry = AuditEntry(**draft, entry_hash=hash_obj(draft))

        self.conn.execute(
            "INSERT INTO audit_log"
            " (idx, entry_id, timestamp, event_type, actor, payload,"
            "  policy_hash, prev_hash, entry_hash)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                entry.index,
                entry.entry_id,
                entry.timestamp,
                entry.event_type.value,
                entry.actor,
                canonical_json(entry.payload),
                entry.policy_hash,
                entry.prev_hash,
                entry.entry_hash,
            ),
        )
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(entry.model_dump(mode="json")) + "\n")
        return entry

    # -- reading -----------------------------------------------------------

    def _row_to_entry(self, row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            index=row["idx"],
            entry_id=row["entry_id"],
            timestamp=row["timestamp"],
            event_type=EventType(row["event_type"]),
            actor=row["actor"],
            payload=json.loads(row["payload"]),
            policy_hash=row["policy_hash"],
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def entries(self) -> list[AuditEntry]:
        rows = self.conn.execute("SELECT * FROM audit_log ORDER BY idx").fetchall()
        return [self._row_to_entry(r) for r in rows]

    def by_case(self, case_id: str) -> list[AuditEntry]:
        return [e for e in self.entries() if e.payload.get("case_id") == case_id]

    def by_type(self, *types: EventType) -> list[AuditEntry]:
        wanted = {EventType(t) for t in types}
        return [e for e in self.entries() if e.event_type in wanted]

    def count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"])

    # -- verification ------------------------------------------------------

    def verify_chain(self) -> ChainVerification:
        """Walk the chain and report the first index that does not check out."""
        prev = ZERO_HASH
        entries = self.entries()
        for i, entry in enumerate(entries):
            if entry.index != i:
                return ChainVerification(
                    ok=False,
                    entries=len(entries),
                    first_broken_index=i,
                    detail=f"index gap: expected {i}, found {entry.index}",
                )
            if entry.prev_hash != prev:
                return ChainVerification(
                    ok=False,
                    entries=len(entries),
                    first_broken_index=entry.index,
                    detail="prev_hash does not match the previous entry's hash",
                )
            recomputed = entry.expected_hash()
            if recomputed != entry.entry_hash:
                return ChainVerification(
                    ok=False,
                    entries=len(entries),
                    first_broken_index=entry.index,
                    detail=(
                        "entry contents do not match entry_hash "
                        f"(stored {entry.entry_hash[:12]}..., "
                        f"recomputed {recomputed[:12]}...)"
                    ),
                )
            prev = entry.entry_hash
        return ChainVerification(ok=True, entries=len(entries), detail="chain intact")

    def close(self) -> None:
        if self._owns_conn:
            self.conn.close()


# --------------------------------------------------------------------------
# Demo helper - deliberately outside the append-only API
# --------------------------------------------------------------------------


def demo_tamper_entry(
    db_path: str | Path, index: int, field: str = "actor", new_value: str = "attacker"
) -> None:
    """DEMO ONLY. Edit one stored entry to show ``verify_chain`` catching it.

    This exists to prove the detection works, so it has to do the thing the
    rest of the module refuses to do: it drops the append-only triggers, writes,
    and puts them back. Nothing in the running system calls it - only
    ``shield tamper``. It is not a supported operation and it leaves the log
    permanently failing verification, which is the point.
    """
    conn = connect(db_path)
    try:
        for name in _TRIGGER_NAMES:
            conn.execute(f"DROP TRIGGER IF EXISTS {name}")
        if field not in {"actor", "event_type", "timestamp", "payload", "policy_hash"}:
            raise ValueError(f"refusing to tamper unknown field {field!r}")
        cur = conn.execute(
            f"UPDATE audit_log SET {field} = ? WHERE idx = ?", (new_value, index)
        )
        if cur.rowcount == 0:
            raise ValueError(f"no audit entry at index {index}")
    finally:
        conn.executescript(_TRIGGERS)
        conn.close()


def iter_jsonl(path: str | Path) -> Iterable[dict]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
