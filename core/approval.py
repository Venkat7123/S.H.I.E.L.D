"""Human approval, bound to one exact action and one exact account state.

An approval here is not "yes, freeze this account". It is "yes, perform
*this* action, on *this* target, backed by *this* evidence, under *this*
policy, while the account is in *this* state" - all of it folded into one
``action_hash``. Change any part and the approval stops matching.

Including the account state is the part people skip, and it closes a real race:
approve a freeze while the account is ACTIVE, something else changes the
account, then the freeze lands against a situation nobody approved. The
executor re-reads the state immediately before writing and recomputes the hash;
a mismatch is ``STATE_CHANGED_SINCE_APPROVAL``, not a write.

Approvals are **single-use** and **expiring**, enforced in storage - the
"mark used" update is conditional on it still being unused, so two concurrent
redemptions cannot both win.

What this cannot do: stop a careless human approving a bad action. The gate
shows raw trusted evidence, flags every untrusted item, and shows disagreement
rather than a tidy summary. The decision is still theirs.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path
from typing import Callable, Protocol

from pydantic import BaseModel, ConfigDict

from core.audit_log import AuditLog, AuditWriteError
from core.canonical import hash_obj
from core.db import DEFAULT_DB, connect
from core.models import (
    AccountState,
    ActionName,
    ApprovalRecord,
    ApprovalRequest,
    EventType,
    StopReason,
    utcnow,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    approval_id  TEXT PRIMARY KEY,
    action_hash  TEXT NOT NULL,
    approver     TEXT NOT NULL,
    account_state TEXT NOT NULL,
    decision     TEXT NOT NULL,
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    used         INTEGER NOT NULL DEFAULT 0
);
"""


def compute_action_hash(
    *,
    case_id: str,
    action: ActionName | str,
    target: str,
    evidence_raw_hashes: list[str],
    policy_hash: str,
    account_state: AccountState | str,
) -> str:
    """The canonical identity of one action in one world-state.

    Sorted evidence hashes so the same evidence in a different order is the
    same action; account state included so approval does not survive the
    account changing underneath it.
    """
    return hash_obj(
        {
            "case_id": case_id,
            "action": ActionName(action).value if not isinstance(action, str) else str(action),
            "target": target,
            "evidence_raw_hashes": sorted(set(evidence_raw_hashes)),
            "policy_hash": policy_hash,
            "account_state": (
                account_state.value
                if isinstance(account_state, AccountState)
                else str(account_state)
            ),
        }
    )


class ApprovalCheck(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    stop_reason: StopReason = StopReason.COMPLETED
    detail: str = ""
    approval_id: str | None = None


class ApprovalPresentation(BaseModel):
    """Everything the human is shown, in the order the PRD fixes.

    The AI-written summary is last and labelled, because whatever a model wrote
    is the least reliable thing on the screen and should not frame what comes
    before it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request: ApprovalRequest
    trusted_evidence: list[dict]
    disagreements: list[dict]
    untrusted_items: list[dict]
    ai_summary: str | None = None


class Decider(Protocol):
    """Whoever answers. CLI prompt, Streamlit button, or a scripted test."""

    def __call__(self, presentation: ApprovalPresentation) -> tuple[str, str]:
        """Return ``(decision, approver)`` where decision is APPROVED/REJECTED."""


def auto_reject(_: ApprovalPresentation) -> tuple[str, str]:
    """Default decider. No human present means no approval."""
    return "REJECTED", "no-approver"


class ApprovalGate:
    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB,
        *,
        audit: AuditLog | None = None,
        policy_hash: str = "",
        now: Callable[[], object] = utcnow,
    ) -> None:
        self.conn = connect(db_path)
        self.conn.executescript(_SCHEMA)
        self.audit = audit
        self.policy_hash = policy_hash
        self._now = now

    # -- issuing -----------------------------------------------------------

    def request(
        self,
        presentation: ApprovalPresentation,
        decider: Decider,
        *,
        ttl_seconds: int,
    ) -> ApprovalRecord:
        """Show the action to a human and record what they said."""
        req = presentation.request
        decision, approver = decider(presentation)
        decision = "APPROVED" if str(decision).upper() == "APPROVED" else "REJECTED"

        issued = self._now()
        record = ApprovalRecord(
            approval_id=f"APPR-{uuid.uuid4().hex[:12]}",
            action_hash=req.action_hash,
            approver=str(approver),
            account_state_at_approval=req.account_state,
            decision=decision,  # type: ignore[arg-type]
            issued_at=issued,
            expires_at=issued + timedelta(seconds=ttl_seconds),
            used=False,
        )
        self.conn.execute(
            "INSERT INTO approvals"
            " (approval_id, action_hash, approver, account_state, decision,"
            "  issued_at, expires_at, used) VALUES (?,?,?,?,?,?,?,0)",
            (
                record.approval_id,
                record.action_hash,
                record.approver,
                record.account_state_at_approval.value,
                record.decision,
                record.issued_at.isoformat(),
                record.expires_at.isoformat(),
            ),
        )
        self._log(
            {
                "case_id": req.case_id,
                "approval_id": record.approval_id,
                "action_hash": record.action_hash,
                "action": req.action.value,
                "target": req.target,
                "account_state": req.account_state.value,
                "decision": record.decision,
                "approver": record.approver,
                "expires_at": record.expires_at.isoformat(),
            }
        )
        return record

    # -- redeeming ---------------------------------------------------------

    def consume(self, approval_id: str, action_hash: str) -> ApprovalCheck:
        """Redeem an approval for exactly one action. Single-use, enforced here."""
        row = self.conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            return ApprovalCheck(
                ok=False,
                stop_reason=StopReason.APPROVAL_MISMATCH,
                detail=f"no such approval: {approval_id}",
            )
        if row["decision"] != "APPROVED":
            return ApprovalCheck(
                ok=False,
                stop_reason=StopReason.APPROVAL_REJECTED,
                detail="the approver rejected this action",
                approval_id=approval_id,
            )
        if row["action_hash"] != action_hash:
            return ApprovalCheck(
                ok=False,
                stop_reason=StopReason.APPROVAL_MISMATCH,
                detail=(
                    "this approval was given for a different action "
                    f"(approved {row['action_hash'][:12]}..., "
                    f"presented {action_hash[:12]}...)"
                ),
                approval_id=approval_id,
            )
        if row["used"]:
            return ApprovalCheck(
                ok=False,
                stop_reason=StopReason.APPROVAL_MISMATCH,
                detail="this approval has already been used; approvals are single-use",
                approval_id=approval_id,
            )
        from datetime import datetime

        expires = datetime.fromisoformat(row["expires_at"])
        if self._now() > expires:
            return ApprovalCheck(
                ok=False,
                stop_reason=StopReason.APPROVAL_EXPIRED,
                detail=f"approval expired at {row['expires_at']}",
                approval_id=approval_id,
            )
        # Conditional update: two redemptions cannot both see used=0 and win.
        cur = self.conn.execute(
            "UPDATE approvals SET used = 1 WHERE approval_id = ? AND used = 0",
            (approval_id,),
        )
        if cur.rowcount != 1:
            return ApprovalCheck(
                ok=False,
                stop_reason=StopReason.APPROVAL_MISMATCH,
                detail="approval was consumed concurrently",
                approval_id=approval_id,
            )
        return ApprovalCheck(ok=True, approval_id=approval_id)

    def get(self, approval_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        return dict(row) if row else None

    def _log(self, payload: dict) -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(EventType.APPROVAL, "approval_gate", payload, self.policy_hash)
        except AuditWriteError:
            pass

    def close(self) -> None:
        self.conn.close()
