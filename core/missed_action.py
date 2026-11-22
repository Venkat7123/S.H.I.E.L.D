"""The missed-action check: catching the attack that works by doing nothing.

Every other control in S.H.I.E.L.D answers "can a hijacked agent make the
system act?" This one answers the opposite question: **can a hijacked agent
stop the system acting when it should?**

A supervisor that has been talked into recommending ``NONE`` leaves no denial,
no alert and no trace. The case closes quietly and the money is gone. So the
executor's threshold arithmetic is run a second time, independently, over the
same verified evidence - and if the threshold *is* met while the proposal was
``NONE``, that disagreement is logged for a human.

It never writes, and it never overrides the proposal. Automating "the agent
said no but we think yes" would hand the write path back to inference, which is
the one thing the architecture refuses to do. A human decides.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.audit_log import AuditLog, AuditWriteError
from core.executor import Executor
from core.models import ActionName, EventType, EvidencePack, Proposal, StopReason
from policy.loader import Policy


class MissedActionFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    missed: bool
    proposed_action: ActionName
    threshold_met: bool
    detail: str = ""
    log_entry_id: str | None = None


def check_for_missed_action(
    *,
    case_id: str,
    proposal: Proposal | None,
    packs: list[EvidencePack],
    executor: Executor,
    policy: Policy,
    audit: AuditLog,
    subject_account: str,
) -> MissedActionFinding:
    """Recompute the threshold and compare it against what was proposed."""
    action = proposal.action if proposal else ActionName.NONE
    if action is not ActionName.NONE:
        return MissedActionFinding(
            case_id=case_id,
            missed=False,
            proposed_action=action,
            threshold_met=False,
            detail="an action was proposed; nothing to check",
        )

    freeze_policy = policy.action(ActionName.FREEZE.value)
    if freeze_policy is None or freeze_policy.threshold is None:
        return MissedActionFinding(
            case_id=case_id,
            missed=False,
            proposed_action=action,
            threshold_met=False,
            detail="no FREEZE threshold configured",
        )

    evidence = executor._verify_evidence(packs)
    result = executor._recompute_threshold(
        case_id, subject_account, evidence, freeze_policy.threshold
    )

    if not result.met:
        return MissedActionFinding(
            case_id=case_id,
            missed=False,
            proposed_action=action,
            threshold_met=False,
            detail=result.detail,
        )

    detail = (
        f"no action was proposed for {subject_account}, but the FREEZE threshold "
        f"is met on the gathered evidence: {result.detail}. "
        "Flagged for human review; nothing was executed."
    )
    entry_id = None
    try:
        entry = audit.append(
            EventType.ALERT,
            "missed_action_check",
            {
                "case_id": case_id,
                "alert": StopReason.MISSED_ACTION.value,
                "subject_account": subject_account,
                "detail": detail,
                "considered_txns": result.considered_txns,
            },
            policy.policy_hash,
        )
        entry_id = entry.entry_id
    except AuditWriteError:
        pass

    return MissedActionFinding(
        case_id=case_id,
        missed=True,
        proposed_action=action,
        threshold_met=True,
        detail=detail,
        log_entry_id=entry_id,
    )
