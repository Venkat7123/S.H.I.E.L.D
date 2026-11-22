"""Escalation: when the system stops and asks a human.

Escalation is not a failure mode. It is the correct answer to "something here
does not add up" - and the one thing that must never follow it is an automated
write. A case that escalates carries its full evidence and disagreement report
to a person, and the executor refuses to act on it at all.

The triggers come from ``policy.escalation.triggers``, so what counts as
"do not proceed" is policy, not scattered conditionals. Two ways a trigger
arrives:

* **observed** - the case runner notices something and calls :meth:`note`
* **derived** - :meth:`scan` reads the audit log and finds the evidence itself

The second matters: it means a component that failed to report a problem
cannot hide it, because the log already recorded the denial or alert.

One-way door: once escalated, a case cannot return to RUNNING.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

from core.audit_log import AuditEntry, AuditLog, AuditWriteError
from core.models import EscalationNotice, EscalationTrigger, EventType
from policy.loader import Policy

# How many malformed results in one case count as "repeated".
MALFORMED_REPEAT_THRESHOLD = 2


def derive_triggers(entries: list[AuditEntry]) -> list[EscalationNotice]:
    """Read a case's log entries and report every trigger they evidence.

    Pure: same entries in, same notices out. Testable without a database.
    """
    notices: list[EscalationNotice] = []
    malformed: list[AuditEntry] = []

    for entry in entries:
        payload = entry.payload
        reason = payload.get("reason")
        alert = payload.get("alert")

        if entry.event_type is EventType.DENIAL and reason == "MALFORMED_OUTPUT":
            malformed.append(entry)
        if reason == "POLICY_TAMPERED" or alert == "POLICY_TAMPERED":
            notices.append(
                EscalationNotice(
                    trigger=EscalationTrigger.POLICY_TAMPERED,
                    log_entry_id=entry.entry_id,
                    detail=str(payload.get("detail") or "policy file changed during the run"),
                )
            )
        if alert == "UNEXPECTED_ERROR":
            notices.append(
                EscalationNotice(
                    trigger=EscalationTrigger.UNEXPECTED_ERROR,
                    log_entry_id=entry.entry_id,
                    detail=str(payload.get("error") or "unexpected error"),
                )
            )

    if len(malformed) >= MALFORMED_REPEAT_THRESHOLD:
        notices.append(
            EscalationNotice(
                trigger=EscalationTrigger.MALFORMED_OUTPUT_REPEATED,
                log_entry_id=malformed[-1].entry_id,
                detail=f"{len(malformed)} malformed tool results in this case",
            )
        )
    return notices


class EscalationTracker:
    """Per-case escalation state. One-way: RUNNING -> ESCALATED, never back."""

    def __init__(self, policy: Policy, audit: AuditLog, case_id: str) -> None:
        self.policy = policy
        self.audit = audit
        self.case_id = case_id
        self._notices: list[EscalationNotice] = []
        self._enabled = set(policy.escalation.triggers)

    @property
    def escalated(self) -> bool:
        return bool(self._notices)

    def notices(self) -> list[EscalationNotice]:
        return list(self._notices)

    def triggers(self) -> list[EscalationTrigger]:
        return [n.trigger for n in self._notices]

    def note(self, trigger: EscalationTrigger, detail: str) -> EscalationNotice | None:
        """Record an observed trigger. Ignored if policy does not enable it."""
        if trigger not in self._enabled:
            return None
        entry_id = "UNLOGGED"
        try:
            entry = self.audit.append(
                EventType.ALERT,
                "escalation",
                {"case_id": self.case_id, "alert": trigger.value, "detail": detail},
                self.policy.policy_hash,
            )
            entry_id = entry.entry_id
        except AuditWriteError:
            pass
        notice = EscalationNotice(trigger=trigger, log_entry_id=entry_id, detail=detail)
        self._add(notice)
        return notice

    def scan(self) -> list[EscalationNotice]:
        """Derive triggers from what the log already records for this case."""
        entries = self.audit.by_case(self.case_id)
        for notice in derive_triggers(entries):
            if notice.trigger in self._enabled:
                self._add(notice)
        return self.notices()

    def _add(self, notice: EscalationNotice) -> None:
        seen = {(n.trigger, n.log_entry_id) for n in self._notices}
        if (notice.trigger, notice.log_entry_id) not in seen:
            self._notices.append(notice)

    def refuse_reason(self) -> str:
        return "; ".join(f"{n.trigger.value}: {n.detail}" for n in self._notices)
