"""Idempotency store: at most one execution per approved action.

The hard case is not the duplicate *request* - it is the lost *response*. A
write lands, the reply is dropped, the caller sees a timeout and retries. Retry
is the right instinct and the wrong action, and it is how an account gets
frozen twice.

So the sequence is ``INTENT -> EXECUTED -> CONFIRMED``, and the state is claimed
*before* the write by an ``INSERT`` on a ``UNIQUE`` key. The insert is the
atomic part: whichever caller wins the insert owns the action, and everyone
else gets ``DUPLICATE_ACTION`` without touching the bank.

The other half is **read back before retry**. After an uncertain write, the
store asks the bank what the state actually is. If the account already reached
the target state, the write succeeded and the response was simply lost: record
``CONFIRMED`` and write nothing further.

Target ids are canonicalised first, so ``acct-0001``, ``ACCT-0001`` and
``ACCT‑0001`` (U+2011 non-breaking hyphen) collapse to one key. Without that,
a Unicode lookalike is a free second write.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict

from core.audit_log import AuditLog, AuditWriteError
from core.canonical import canonicalize_account, sha256_hex
from core.db import DEFAULT_DB, connect
from core.models import EventType, IdempotencyState, StopReason, utcnow
from policy.loader import CanonicalizeTarget

_SCHEMA = """
CREATE TABLE IF NOT EXISTS idempotency (
    key          TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    state        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
"""


class WriteResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    key: str
    state: IdempotencyState | None = None
    stop_reason: StopReason = StopReason.COMPLETED
    detail: str = ""
    wrote: bool = False  # did this call actually touch the bank?


class IdempotencyStore:
    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB,
        *,
        audit: AuditLog | None = None,
        policy_hash: str = "",
        canonicalize: CanonicalizeTarget | None = None,
    ) -> None:
        self.conn = connect(db_path)
        self.conn.executescript(_SCHEMA)
        self.audit = audit
        self.policy_hash = policy_hash
        self.canon = canonicalize or CanonicalizeTarget()

    # -- keys --------------------------------------------------------------

    def canonical_target(self, target: str) -> str:
        return canonicalize_account(
            target,
            upper=self.canon.upper,
            strip=self.canon.strip,
            normalize_unicode_hyphens=self.canon.normalize_unicode_hyphens,
        )

    def key_for(self, case_id: str, action: str, target: str) -> str:
        return sha256_hex(f"{case_id}|{action}|{self.canonical_target(target)}")

    # -- state -------------------------------------------------------------

    def get(self, key: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM idempotency WHERE key = ?", (key,)
        ).fetchone()
        return dict(row) if row else None

    def _log(self, key: str, state: str, extra: dict) -> None:
        if self.audit is None:
            return
        try:
            # ``state`` is written last so a caller's payload cannot overwrite
            # the state transition this entry exists to record.
            self.audit.append(
                EventType.ACTION,
                "executor",
                {"idempotency_key": key, **extra, "state": state},
                self.policy_hash,
            )
        except AuditWriteError:
            pass

    def _advance(self, key: str, state: IdempotencyState, extra: dict) -> None:
        self.conn.execute(
            "UPDATE idempotency SET state = ?, updated_at = ? WHERE key = ?",
            (state.value, utcnow().isoformat(), key),
        )
        self._log(key, state.value, extra)

    # -- the write path ----------------------------------------------------

    def execute(
        self,
        *,
        case_id: str,
        action: str,
        target: str,
        payload_hash: str,
        desired_state: str,
        write: Callable[[str], object],
        read_back: Callable[[], str | None],
        write_response_unknown: Callable[[object], bool] = lambda r: False,
    ) -> WriteResult:
        """Run one action at most once.

        ``write`` receives the idempotency key and performs the write.
        ``read_back`` returns the account's current state from the bank.
        ``write_response_unknown`` says whether a returned outcome means
        "it may have happened" rather than "it failed".
        """
        canonical = self.canonical_target(target)
        key = self.key_for(case_id, action, target)
        now = utcnow().isoformat()

        # -- claim the action atomically --------------------------------
        try:
            self.conn.execute(
                "INSERT INTO idempotency"
                " (key, case_id, action, target, payload_hash, state, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    key,
                    case_id,
                    action,
                    canonical,
                    payload_hash,
                    IdempotencyState.INTENT.value,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            existing = self.get(key) or {}
            if existing.get("payload_hash") != payload_hash:
                self._log(key, "IDEMPOTENCY_CONFLICT", {"case_id": case_id, "action": action})
                return WriteResult(
                    ok=False,
                    key=key,
                    state=IdempotencyState(existing["state"]) if existing else None,
                    stop_reason=StopReason.IDEMPOTENCY_CONFLICT,
                    detail=(
                        "this key was already used for a different action payload; "
                        "refusing to overwrite"
                    ),
                )
            self._log(key, "DUPLICATE_ACTION", {"case_id": case_id, "action": action})
            return WriteResult(
                ok=False,
                key=key,
                state=IdempotencyState(existing["state"]) if existing else None,
                stop_reason=StopReason.DUPLICATE_ACTION,
                detail=f"action already claimed (state={existing.get('state')})",
            )

        self._log(key, IdempotencyState.INTENT.value, {"case_id": case_id, "action": action, "target": canonical})

        # -- already there? then there is nothing to do -------------------
        current = read_back()
        if current == desired_state:
            self._advance(
                key,
                IdempotencyState.CONFIRMED,
                {"case_id": case_id, "note": "already in target state; no write issued"},
            )
            return WriteResult(
                ok=True,
                key=key,
                state=IdempotencyState.CONFIRMED,
                detail=f"account already {desired_state}; no write issued",
                wrote=False,
            )

        # -- write --------------------------------------------------------
        outcome = write(key)
        uncertain = write_response_unknown(outcome)

        if uncertain:
            # The write may have landed. Ask the bank rather than guessing.
            after = read_back()
            if after == desired_state:
                self._advance(
                    key,
                    IdempotencyState.EXECUTED,
                    {"case_id": case_id, "note": "response lost; read-back shows the write landed"},
                )
                self._advance(key, IdempotencyState.CONFIRMED, {"case_id": case_id})
                return WriteResult(
                    ok=True,
                    key=key,
                    state=IdempotencyState.CONFIRMED,
                    detail="response was lost in transit; read-back confirmed the write. "
                    "No second write issued.",
                    wrote=True,
                )
            self._log(key, "WRITE_UNCONFIRMED", {"case_id": case_id, "read_back": after})
            return WriteResult(
                ok=False,
                key=key,
                state=IdempotencyState.INTENT,
                stop_reason=StopReason.TIMEOUT,
                detail=f"write outcome unknown and read-back shows {after!r}",
                wrote=False,
            )

        if outcome is None:
            self._log(key, "WRITE_FAILED", {"case_id": case_id})
            return WriteResult(
                ok=False,
                key=key,
                state=IdempotencyState.INTENT,
                stop_reason=StopReason.TOOL_FAILURE,
                detail="write failed",
                wrote=False,
            )

        self._advance(key, IdempotencyState.EXECUTED, {"case_id": case_id, "action": action})

        after = read_back()
        if after != desired_state:
            self._log(key, "CONFIRM_FAILED", {"case_id": case_id, "read_back": after})
            return WriteResult(
                ok=False,
                key=key,
                state=IdempotencyState.EXECUTED,
                stop_reason=StopReason.TOOL_FAILURE,
                detail=f"write reported success but read-back shows {after!r}",
                wrote=True,
            )

        self._advance(key, IdempotencyState.CONFIRMED, {"case_id": case_id, "account_state": after})
        return WriteResult(
            ok=True,
            key=key,
            state=IdempotencyState.CONFIRMED,
            detail=f"account is {after}",
            wrote=True,
        )

    def close(self) -> None:
        self.conn.close()
