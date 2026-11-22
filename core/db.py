"""SQLite connection helper.

One file holds the mock bank, the audit log and the idempotency store so a
demo run is a single artefact you can inspect or delete. Every connection gets
the same pragmas, so append-only triggers and unique constraints behave the
same everywhere.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DEFAULT_DB = "data/shield.db"


def connect(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    return conn
