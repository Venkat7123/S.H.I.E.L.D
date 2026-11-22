"""Content-addressed store for raw tool output.

Agents never pass raw text onward - they pass ``raw_hash`` plus
``record_refs``. The executor reloads the real bytes from here and recomputes
everything it needs. That closes the gap where an agent summarises, paraphrases
or quietly edits what a tool returned.

A record ref is ``<kind>:<id>`` with an optional ``.<field>`` suffix:

* ``txn:TXN-0042`` - the whole transaction record
* ``txn:TXN-0042.to_account`` - one field of it
* ``note:NOTE-0002.body`` - one field of a case note

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.canonical import canonical_json, sha256_hex
from core.db import DEFAULT_DB, connect

_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_outputs (
    raw_hash  TEXT PRIMARY KEY,
    tool      TEXT NOT NULL,
    stored_at TEXT NOT NULL,
    content   TEXT NOT NULL
);
"""


class RawStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB) -> None:
        self.conn = connect(db_path)
        self.conn.executescript(_SCHEMA)

    def put(self, tool: str, payload: Any) -> str:
        """Store raw output, return its hash. Idempotent by content."""
        blob = canonical_json(payload)
        raw_hash = sha256_hex(blob)
        from core.models import utcnow

        self.conn.execute(
            "INSERT OR IGNORE INTO raw_outputs (raw_hash, tool, stored_at, content)"
            " VALUES (?,?,?,?)",
            (raw_hash, tool, utcnow().isoformat(), blob),
        )
        return raw_hash

    def get(self, raw_hash: str) -> Any | None:
        row = self.conn.execute(
            "SELECT content FROM raw_outputs WHERE raw_hash = ?", (raw_hash,)
        ).fetchone()
        return json.loads(row["content"]) if row else None

    def tool_of(self, raw_hash: str) -> str | None:
        """Which tool produced this payload.

        The executor derives an evidence item's source system from this, not
        from the item's own ``source_system`` field - an agent can write
        anything it likes in a pack, but it cannot change which tool actually
        ran.
        """
        row = self.conn.execute(
            "SELECT tool FROM raw_outputs WHERE raw_hash = ?", (raw_hash,)
        ).fetchone()
        return row["tool"] if row else None

    def has(self, raw_hash: str) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM raw_outputs WHERE raw_hash = ?", (raw_hash,)
            ).fetchone()
            is not None
        )

    # -- record refs -------------------------------------------------------

    @staticmethod
    def parse_ref(ref: str) -> tuple[str, str, str | None]:
        """``"txn:TXN-0042.to_account"`` -> ``("txn", "TXN-0042", "to_account")``."""
        kind, _, rest = ref.partition(":")
        if not rest:
            raise ValueError(f"malformed record ref: {ref!r}")
        record_id, dot, field = rest.partition(".")
        return kind, record_id, (field if dot else None)

    def resolve(self, raw_hash: str, ref: str) -> Any | None:
        """Return the value a ref points at, or None if it does not exist.

        Used to verify that cited evidence is real before any of it counts.
        """
        payload = self.get(raw_hash)
        if payload is None:
            return None
        try:
            _kind, record_id, field = self.parse_ref(ref)
        except ValueError:
            return None
        records = payload if isinstance(payload, list) else [payload]
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if self.record_id_of(rec) != record_id:
                continue
            if field is None:
                return rec
            return rec.get(field) if field in rec else None
        return None

    def ref_exists(self, raw_hash: str, ref: str) -> bool:
        return self.resolve(raw_hash, ref) is not None

    @staticmethod
    def record_id_of(record: dict) -> str | None:
        for key in ("txn_id", "note_id", "account_id", "case_id"):
            if key in record:
                return str(record[key])
        return None

    @staticmethod
    def kind_of(record: dict) -> str:
        if "txn_id" in record:
            return "txn"
        if "note_id" in record:
            return "note"
        if "case_id" in record:
            return "case"
        if "account_id" in record:
            return "acct"
        return "rec"

    def close(self) -> None:
        self.conn.close()
