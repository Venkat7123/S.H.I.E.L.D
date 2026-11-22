"""The mock bank's three tools.

===========================  ======  =======================================
``query_transactions``       READ    workers, per their work order
``read_case_notes``          READ    workers, per their work order
``set_account_status``       WRITE   **executor only** - never an agent
===========================  ======  =======================================

``get_account_status`` is deliberately *not* a tool. It is an internal,
executor-only read used for the idempotency read-back. Exposing it as a tool
would put a second surface on the account table for no benefit.

Nothing here enforces permissions. Enforcement is the gateway's job and lives
in one place; a tool that also checked would be a second, divergent copy of the
rules. These functions assume they are only reached through the gateway.

Time inside the bank runs from :data:`data.seed.ANCHOR`, not from the wall
clock, so ``days=30`` selects the same rows on every run.
"""

from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from core.db import DEFAULT_DB, connect
from data.seed import ANCHOR
from tools.failure_injection import DroppedResponse, FailureInjector


class ToolError(Exception):
    """Transient failure. The gateway may retry within budget."""


class ToolTimeout(ToolError):
    pass


class MalformedToolOutput(Exception):
    """Output that does not match the tool's contract. Discarded, never used."""


class BankTools:
    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB,
        injector: FailureInjector | None = None,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.db_path = str(db_path)
        self.conn = connect(db_path)
        self.injector = injector or FailureInjector()
        self.timeout_seconds = timeout_seconds

    # -- fault handling ----------------------------------------------------

    def _pre(self, tool: str) -> "object | None":
        """Apply any armed fault that fires *before* the real work."""
        fault = self.injector.next_fault(tool)
        if fault is None:
            return None
        if fault.delay_seconds:
            # Sleep only as far as the timeout, then raise: a test should not
            # wait out a 30-second delay to prove a 5-second timeout works.
            time.sleep(min(fault.delay_seconds, self.timeout_seconds))
            if fault.delay_seconds >= self.timeout_seconds:
                raise ToolTimeout(
                    f"{tool} exceeded {self.timeout_seconds}s ({fault.message})"
                )
        if fault.raise_error:
            raise ToolError(f"{tool} failed: {fault.message}")
        return fault

    # -- READ tools --------------------------------------------------------

    def query_transactions(self, account_id: str, days: int) -> list[dict]:
        fault = self._pre("query_transactions")
        cutoff = (ANCHOR - timedelta(days=days)).isoformat()
        rows = self.conn.execute(
            "SELECT txn_id, from_account, to_account, amount, currency,"
            "       timestamp, channel, description"
            "  FROM transactions"
            " WHERE (from_account = ? OR to_account = ?) AND timestamp >= ?"
            " ORDER BY timestamp",
            (account_id, account_id, cutoff),
        ).fetchall()
        out = [dict(r) for r in rows]
        if fault is not None and fault.malformed:
            return self._corrupt(out)
        if fault is not None and fault.drop_response:
            raise DroppedResponse("query_transactions response lost in transit")
        return out

    def read_case_notes(self, account_id: str, limit: int) -> list[dict]:
        fault = self._pre("read_case_notes")
        rows = self.conn.execute(
            "SELECT note_id, account_id, source, created_at, body"
            "  FROM case_notes WHERE account_id = ?"
            " ORDER BY created_at DESC LIMIT ?",
            (account_id, limit),
        ).fetchall()
        out = [dict(r) for r in rows]
        if fault is not None and fault.malformed:
            return self._corrupt(out)
        if fault is not None and fault.drop_response:
            raise DroppedResponse("read_case_notes response lost in transit")
        return out

    @staticmethod
    def _corrupt(rows: list[dict]) -> list[dict]:
        """Shape-break the output so schema validation rejects it."""
        return [{"garbage": True, "rows": len(rows)}, "not-a-record"]  # type: ignore[list-item]

    # -- WRITE tool (executor only) ---------------------------------------

    def set_account_status(
        self, account_id: str, action: str, idempotency_key: str
    ) -> dict:
        """Freeze or unfreeze. Reached only via the executor, via the gateway."""
        fault = self._pre("set_account_status")
        if action not in ("FREEZE", "UNFREEZE"):
            raise MalformedToolOutput(f"unknown action {action!r}")
        new_status = "FROZEN" if action == "FREEZE" else "ACTIVE"
        cur = self.conn.execute(
            "UPDATE accounts SET status = ? WHERE account_id = ?",
            (new_status, account_id),
        )
        if cur.rowcount == 0:
            raise ToolError(f"no such account: {account_id}")
        result = {
            "account_id": account_id,
            "status": new_status,
            "idempotency_key": idempotency_key,
        }
        if fault is not None and fault.drop_response:
            # The write above is committed. The caller is about to be told
            # nothing happened. This is scenario A8.
            raise DroppedResponse("set_account_status response lost in transit")
        return result

    # -- internal, executor-only ------------------------------------------

    def get_account_status(self, account_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT status FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return row["status"] if row else None

    def account_exists(self, account_id: str) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            is not None
        )

    def get_case(self, case_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_account(self, account_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.conn.close()


# Output contract per tool, checked by the gateway at step 10.
REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "query_transactions": frozenset(
        {
            "txn_id",
            "from_account",
            "to_account",
            "amount",
            "currency",
            "timestamp",
            "channel",
            "description",
        }
    ),
    "read_case_notes": frozenset(
        {"note_id", "account_id", "source", "created_at", "body"}
    ),
    "set_account_status": frozenset({"account_id", "status", "idempotency_key"}),
}


def validate_output(tool: str, payload: object) -> str | None:
    """Return None if the output matches the tool's contract, else why not."""
    required = REQUIRED_FIELDS.get(tool)
    if required is None:
        return f"no output contract registered for {tool!r}"
    records = payload if isinstance(payload, list) else [payload]
    if not isinstance(records, list):
        return "output is not a list of records"
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            return f"record {i} is {type(rec).__name__}, expected object"
        missing = required - set(rec)
        if missing:
            return f"record {i} missing field(s): {sorted(missing)}"
    return None
