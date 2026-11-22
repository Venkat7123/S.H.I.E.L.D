"""The executor: the only thing in the system that can cause a write.

The supervisor *proposes*. This proposes nothing and believes nothing. It takes
a ``Proposal`` as a claim to be checked and re-derives every fact behind it from
storage:

* the **target** must verify against the provenance ledger *and* be in the
  allowed set the executor computes itself from TRUSTED fields;
* the **evidence** must resolve to raw bytes that are still there and still
  match, and its source system is taken from the raw store's record of which
  tool produced it - not from what the pack says;
* the **threshold** is recomputed from those raw TRUSTED fields, here, in
  plain arithmetic. The agents' confidence levels are not an input.

A proposal can therefore be entirely fabricated and still be harmless: nothing
it asserts is used as a reason to act.

Order matters. Escalation is checked before anything else, the target before
the threshold, and the account state is re-read *after* approval and
immediately before the write, because that is the window in which the world can
change behind a human's decision.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict

from core.approval import (
    ApprovalGate,
    ApprovalPresentation,
    Decider,
    compute_action_hash,
)
from core.audit_log import AuditLog, AuditWriteError
from core.escalation import EscalationTracker
from core.gateway import Gateway
from core.idempotency import IdempotencyStore
from core.models import (
    AccountState,
    ActionName,
    ActionOutcome,
    ApprovalRequest,
    ComparisonReport,
    EscalationTrigger,
    EventType,
    EvidenceItem,
    EvidencePack,
    GatewayDenial,
    Proposal,
    StopReason,
    ToolResult,
    Trust,
)
from core.provenance import ProvenanceLedger
from core.raw_store import RawStore
from policy.loader import Policy, Threshold
from tools.bank import BankTools

# Which system of record each tool speaks for. Derived from the raw store's
# own record of which tool produced a payload, never from the evidence pack.
TOOL_SOURCE_SYSTEM = {
    "query_transactions": "transactions_db",
    "read_case_notes": "notes_store",
    "set_account_status": "accounts_db",
}


class VerifiedEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    items: list[EvidenceItem]
    raw_hashes: list[str]
    rejected: list[str]
    source_systems: list[str]


class ThresholdResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    met: bool
    total_inbound: int = 0
    inbound_from_new_accounts: int = 0
    hours_inbound_to_outbound: float | None = None
    trigger_txn: str | None = None
    considered_txns: list[str] = []
    detail: str = ""


class Executor:
    def __init__(
        self,
        *,
        policy: Policy,
        audit: AuditLog,
        gateway: Gateway,
        ledger: ProvenanceLedger,
        raw_store: RawStore,
        idempotency: IdempotencyStore,
        approvals: ApprovalGate,
        tools: BankTools,
        enable_independent_sources: bool = False,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.gateway = gateway
        self.ledger = ledger
        self.raw = raw_store
        self.idempotency = idempotency
        self.approvals = approvals
        self.tools = tools
        self.enable_independent_sources = enable_independent_sources

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def execute(
        self,
        *,
        case_id: str,
        proposal: Proposal,
        packs: list[EvidencePack],
        comparison: ComparisonReport,
        escalation: EscalationTracker,
        decider: Decider,
        ai_summary: str | None = None,
    ) -> ActionOutcome:
        def refuse(reason: StopReason, detail: str, **extra) -> ActionOutcome:
            self._log(
                EventType.DECISION,
                {
                    "case_id": case_id,
                    "outcome": "REFUSED",
                    "stop_reason": reason.value,
                    "detail": detail,
                    "proposal_id": proposal.proposal_id,
                    **extra,
                },
            )
            return ActionOutcome(
                case_id=case_id,
                action=proposal.action,
                target=None,
                executed=False,
                stop_reason=reason,
                detail=detail,
                **{k: v for k, v in extra.items() if k in {"action_hash", "approval_id"}},
            )

        # -- 0. an escalated case has no write path ---------------------
        escalation.scan()
        if escalation.escalated:
            return refuse(
                StopReason.ESCALATED,
                "case is escalated; the write path is closed. "
                f"Triggers: {escalation.refuse_reason()}",
            )

        if proposal.action is ActionName.NONE:
            self._log(
                EventType.DECISION,
                {"case_id": case_id, "outcome": "NO_ACTION_PROPOSED"},
            )
            return ActionOutcome(
                case_id=case_id,
                action=ActionName.NONE,
                target=None,
                executed=False,
                stop_reason=StopReason.COMPLETED,
                detail="no action proposed",
            )

        # -- 1. proposal integrity --------------------------------------
        if proposal.case_id != case_id:
            return refuse(
                StopReason.DENIED,
                f"proposal is for case {proposal.case_id!r}, not {case_id!r}",
            )
        if proposal.policy_hash != self.policy.policy_hash:
            return refuse(
                StopReason.POLICY_TAMPERED,
                "proposal was made under a different policy hash",
            )
        action_policy = self.policy.action(proposal.action.value)
        if action_policy is None:
            return refuse(StopReason.DENIED, f"action {proposal.action.value!r} is not in policy")

        # -- 2. trusted target ------------------------------------------
        target_check = self._check_target(case_id, proposal)
        if target_check is not None:
            return refuse(StopReason.UNTRUSTED_TARGET, target_check)
        target = str(proposal.target.value)

        # -- 3. evidence resolves to real, unchanged raw output -----------
        evidence = self._verify_evidence(packs)
        if evidence.rejected:
            self._log(
                EventType.ALERT,
                {
                    "case_id": case_id,
                    "alert": "EVIDENCE_REJECTED",
                    "rejected": evidence.rejected,
                },
            )
        if not evidence.items:
            return refuse(
                StopReason.THRESHOLD_NOT_MET,
                "no evidence item survived verification against stored raw output",
            )

        # -- 4. recompute the threshold ourselves -------------------------
        threshold = self._recompute_threshold(case_id, target, evidence, action_policy.threshold)
        self._log(
            EventType.DECISION,
            {
                "case_id": case_id,
                "check": "THRESHOLD",
                "met": threshold.met,
                **threshold.model_dump(mode="json", exclude={"met", "detail"}),
                "detail": threshold.detail,
            },
        )
        if not threshold.met:
            return refuse(StopReason.THRESHOLD_NOT_MET, threshold.detail)

        # -- 5. independent sources (optional) ----------------------------
        if self.enable_independent_sources and action_policy.min_independent_sources:
            sources = set(evidence.source_systems)
            if threshold.inbound_from_new_accounts:
                # Counterparty ages came from the accounts system of record,
                # which the executor read itself.
                sources.add("accounts_db")
            if len(sources) < action_policy.min_independent_sources:
                return refuse(
                    StopReason.INSUFFICIENT_INDEPENDENT_SOURCES,
                    f"evidence rests on {len(sources)} independent source(s) "
                    f"({sorted(sources)}); policy requires "
                    f"{action_policy.min_independent_sources}",
                )

        # -- 6. bind the action to the account's current state -------------
        state_before = self._account_state(target)
        if state_before is None:
            return refuse(StopReason.UNTRUSTED_TARGET, f"{target} is not a known account")
        action_hash = compute_action_hash(
            case_id=case_id,
            action=proposal.action,
            target=target,
            evidence_raw_hashes=evidence.raw_hashes,
            policy_hash=self.policy.policy_hash,
            account_state=state_before,
        )

        # -- 7. ask a human -----------------------------------------------
        if not action_policy.requires_approval:
            return refuse(
                StopReason.DENIED,
                "policy marks this action as not requiring approval; "
                "S.H.I.E.L.D does not perform unapproved writes",
            )
        presentation = self._present(
            case_id=case_id,
            proposal=proposal,
            target=target,
            state=state_before,
            evidence=evidence,
            comparison=comparison,
            packs=packs,
            action_hash=action_hash,
            ttl=action_policy.approval_ttl_seconds,
            ai_summary=ai_summary,
        )
        record = self.approvals.request(
            presentation, decider, ttl_seconds=action_policy.approval_ttl_seconds
        )
        if record.decision != "APPROVED":
            return refuse(
                StopReason.APPROVAL_REJECTED,
                f"{record.approver} rejected this action",
                action_hash=action_hash,
                approval_id=record.approval_id,
            )

        # -- 8. re-read state and re-bind, immediately before writing -------
        state_now = self._account_state(target)
        hash_now = compute_action_hash(
            case_id=case_id,
            action=proposal.action,
            target=target,
            evidence_raw_hashes=evidence.raw_hashes,
            policy_hash=self.policy.policy_hash,
            account_state=state_now or "UNKNOWN",
        )
        if hash_now != action_hash:
            escalation.note(
                EscalationTrigger.UNEXPECTED_ERROR,
                f"{target} changed from {state_before.value} to {state_now} "
                "between approval and execution",
            )
            return refuse(
                StopReason.STATE_CHANGED_SINCE_APPROVAL,
                f"{target} was {state_before.value} when approved and is {state_now} now; "
                "the approval no longer matches this action",
                action_hash=action_hash,
                approval_id=record.approval_id,
            )

        check = self.approvals.consume(record.approval_id, action_hash)
        if not check.ok:
            return refuse(
                check.stop_reason,
                check.detail,
                action_hash=action_hash,
                approval_id=record.approval_id,
            )

        # -- 9. write, once --------------------------------------------------
        return self._write(
            case_id=case_id,
            proposal=proposal,
            target=target,
            action_hash=action_hash,
            approval_id=record.approval_id,
        )

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_target(self, case_id: str, proposal: Proposal) -> str | None:
        """Return None if the target is acceptable, else why it is not.

        Three independent hurdles, because each catches a different lie:
        the *label* must say TRUSTED, the *ledger* must agree it really is,
        and the value must be in a set this function computed from storage.
        """
        lv = proposal.target
        if lv.trust is not Trust.TRUSTED:
            return (
                f"target {lv.value!r} is labelled {lv.trust.value}; "
                "only TRUSTED values from a system of record may name a target"
            )

        verification = self.ledger.verify(lv)
        if not verification.ok:
            return f"target label does not verify against provenance: {verification.reason}"

        target = str(lv.value)
        case = self.tools.get_case(case_id)
        if case is None:
            return f"unknown case {case_id!r}"

        allowed: set[str] = set()
        rules = self.policy.action(proposal.action.value)
        must_be = rules.target_must_be if rules else []
        if "case_subject" in must_be:
            allowed.add(case["subject_account"])
        if "trusted_counterparty" in must_be:
            allowed |= self.ledger.trusted_account_values(case_id)

        if target not in allowed:
            return (
                f"{target} is not the case subject and did not reach this case "
                "through a TRUSTED field of a system of record"
            )
        if not self.tools.account_exists(target):
            return f"{target} does not exist in the accounts system of record"
        return None

    def _verify_evidence(self, packs: list[EvidencePack]) -> VerifiedEvidence:
        """Keep only evidence whose raw output is present and whose refs resolve."""
        kept: list[EvidenceItem] = []
        rejected: list[str] = []
        hashes: list[str] = []
        systems: list[str] = []

        for pack in packs:
            for item in pack.evidence_items:
                if not self.raw.has(item.raw_hash):
                    rejected.append(f"{item.item_id}: raw output {item.raw_hash[:12]}... not stored")
                    continue
                actual_tool = self.raw.tool_of(item.raw_hash)
                actual_system = TOOL_SOURCE_SYSTEM.get(actual_tool or "", "unknown")
                if actual_system != item.source_system:
                    rejected.append(
                        f"{item.item_id}: claims {item.source_system}, "
                        f"raw output came from {actual_tool!r} ({actual_system})"
                    )
                    continue
                missing = [r for r in item.record_refs if not self.raw.ref_exists(item.raw_hash, r)]
                if missing:
                    rejected.append(f"{item.item_id}: cites refs that do not exist: {missing}")
                    continue
                kept.append(item)
                if item.trust is Trust.TRUSTED:
                    hashes.append(item.raw_hash)
                    systems.append(actual_system)

        return VerifiedEvidence(
            items=kept,
            raw_hashes=sorted(set(hashes)),
            rejected=rejected,
            source_systems=sorted(set(systems)),
        )

    def _recompute_threshold(
        self,
        case_id: str,
        target: str,
        evidence: VerifiedEvidence,
        threshold: Threshold | None,
    ) -> ThresholdResult:
        """Decide whether the pattern is really there, from raw TRUSTED fields.

        Reads the transactions the workers actually gathered - so the executor
        is not conducting its own separate investigation - but reads them
        itself, ignoring every interpretation the agents put on them.
        ``description`` is never consulted: it is UNTRUSTED at origin.
        """
        if threshold is None:
            return ThresholdResult(met=True, detail="no threshold configured for this action")

        txns = self._trusted_transactions(evidence)
        if not txns:
            return ThresholdResult(
                met=False,
                detail="no TRUSTED transaction records were gathered for this case",
            )

        inbound = [t for t in txns if t["to_account"] == target]
        outbound = sorted(
            (t for t in txns if t["from_account"] == target), key=lambda t: t["timestamp"]
        )
        if not outbound:
            return ThresholdResult(
                met=False,
                considered_txns=sorted(t["txn_id"] for t in inbound),
                total_inbound=sum(int(t["amount"]) for t in inbound),
                detail=f"no outbound transaction from {target} in the gathered evidence",
            )

        window = timedelta(hours=threshold.max_hours_inbound_to_outbound)
        age_limit = timedelta(days=threshold.new_account_age_days)
        best: ThresholdResult | None = None

        for out in outbound:
            out_at = _parse(out["timestamp"])
            cluster = [t for t in inbound if timedelta(0) <= out_at - _parse(t["timestamp"]) <= window]
            if not cluster:
                continue
            total = sum(int(t["amount"]) for t in cluster)
            new_counterparties = set()
            for t in cluster:
                acct = self.tools.get_account(t["from_account"])
                if acct is None:
                    continue
                if _parse(t["timestamp"]) - _parse(acct["opened_at"]) < age_limit:
                    new_counterparties.add(t["from_account"])
            last_in = max(_parse(t["timestamp"]) for t in cluster)
            gap_hours = (out_at - last_in).total_seconds() / 3600.0

            result = ThresholdResult(
                met=(
                    len(new_counterparties) >= threshold.min_inbound_from_new_accounts
                    and total >= threshold.min_total_inbound
                    and gap_hours <= threshold.max_hours_inbound_to_outbound
                ),
                total_inbound=total,
                inbound_from_new_accounts=len(new_counterparties),
                hours_inbound_to_outbound=round(gap_hours, 2),
                trigger_txn=out["txn_id"],
                considered_txns=sorted(t["txn_id"] for t in cluster),
            )
            if result.met:
                return result.model_copy(
                    update={
                        "detail": (
                            f"{result.inbound_from_new_accounts} inbound transfers from accounts "
                            f"opened within {threshold.new_account_age_days} days, totalling "
                            f"{result.total_inbound}, followed by {out['txn_id']} after "
                            f"{result.hours_inbound_to_outbound}h"
                        )
                    }
                )
            if best is None or result.total_inbound > best.total_inbound:
                best = result

        if best is None:
            return ThresholdResult(
                met=False,
                detail=(
                    f"no inbound transfers within "
                    f"{threshold.max_hours_inbound_to_outbound}h before any outbound"
                ),
            )
        return best.model_copy(
            update={
                "detail": (
                    "threshold not met: "
                    f"{best.inbound_from_new_accounts}/{threshold.min_inbound_from_new_accounts} "
                    f"new-account inbounds, {best.total_inbound}/{threshold.min_total_inbound} "
                    f"total inbound, {best.hours_inbound_to_outbound}h/"
                    f"{threshold.max_hours_inbound_to_outbound}h to outbound"
                )
            }
        )

    def _trusted_transactions(self, evidence: VerifiedEvidence) -> list[dict]:
        """Raw transaction records, with the UNTRUSTED ``description`` stripped.

        Removing the field rather than ignoring it by convention means no later
        edit to this file can accidentally start reading it.
        """
        seen: dict[str, dict] = {}
        for raw_hash in {
            i.raw_hash for i in evidence.items if i.trust is Trust.TRUSTED
        }:
            if self.raw.tool_of(raw_hash) != "query_transactions":
                continue
            payload = self.raw.get(raw_hash) or []
            for rec in payload if isinstance(payload, list) else [payload]:
                if not isinstance(rec, dict) or "txn_id" not in rec:
                    continue
                seen[rec["txn_id"]] = {k: v for k, v in rec.items() if k != "description"}
        return list(seen.values())

    # ------------------------------------------------------------------
    # Presentation and writing
    # ------------------------------------------------------------------

    def _present(
        self,
        *,
        case_id: str,
        proposal: Proposal,
        target: str,
        state: AccountState,
        evidence: VerifiedEvidence,
        comparison: ComparisonReport,
        packs: list[EvidencePack],
        action_hash: str,
        ttl: int,
        ai_summary: str | None,
    ) -> ApprovalPresentation:
        trusted_rows: list[dict] = []
        untrusted_rows: list[dict] = []
        for item in evidence.items:
            row = {
                "item_id": item.item_id,
                "source_system": item.source_system,
                "tool": item.source_tool,
                "raw_hash": item.raw_hash[:16] + "...",
                "record_refs": item.record_refs,
                "trust": item.trust.value,
            }
            (trusted_rows if item.trust is Trust.TRUSTED else untrusted_rows).append(row)

        disagreements = [
            {
                "subject": g.subject,
                "predicate": g.predicate.value,
                "asserted_by": [
                    f"{c.worker_role} ({c.confidence})" for c in g.asserted
                ],
                "denied_by": [f"{c.worker_role} ({c.confidence})" for c in g.denied],
            }
            for g in comparison.conflicts
        ]

        return ApprovalPresentation(
            request=ApprovalRequest(
                action_hash=action_hash,
                case_id=case_id,
                action=proposal.action,
                target=target,
                account_state=state,
                policy_hash=self.policy.policy_hash,
                evidence_raw_hashes=evidence.raw_hashes,
                ttl_seconds=ttl,
            ),
            trusted_evidence=trusted_rows,
            disagreements=disagreements,
            untrusted_items=untrusted_rows,
            ai_summary=ai_summary,
        )

    def _write(
        self,
        *,
        case_id: str,
        proposal: Proposal,
        target: str,
        action_hash: str,
        approval_id: str,
    ) -> ActionOutcome:
        desired = "FROZEN" if proposal.action is ActionName.FREEZE else "ACTIVE"
        client = self.gateway.executor_client(case_id)
        captured: dict[str, object] = {}

        def do_write(key: str):
            outcome = client.call(
                "set_account_status",
                account_id=target,
                action=proposal.action.value,
                idempotency_key=key,
            )
            captured["outcome"] = outcome
            if isinstance(outcome, ToolResult):
                return outcome
            return None if not getattr(outcome, "response_unknown", False) else outcome

        def response_unknown(result) -> bool:
            return isinstance(result, GatewayDenial) and result.response_unknown

        write_result = self.idempotency.execute(
            case_id=case_id,
            action=proposal.action.value,
            target=target,
            payload_hash=action_hash,
            desired_state=desired,
            write=do_write,
            read_back=lambda: self.tools.get_account_status(target),
            write_response_unknown=response_unknown,
        )

        self._log(
            EventType.ACTION,
            {
                "case_id": case_id,
                "action": proposal.action.value,
                "target": target,
                "action_hash": action_hash,
                "approval_id": approval_id,
                "idempotency_key": write_result.key,
                "state": write_result.state.value if write_result.state else None,
                "executed": write_result.ok,
                "wrote": write_result.wrote,
                "detail": write_result.detail,
            },
        )
        return ActionOutcome(
            case_id=case_id,
            action=proposal.action,
            target=target,
            executed=write_result.ok,
            stop_reason=write_result.stop_reason,
            action_hash=action_hash,
            approval_id=approval_id,
            idempotency_state=write_result.state,
            detail=write_result.detail,
        )

    # ------------------------------------------------------------------

    def _account_state(self, target: str) -> AccountState | None:
        raw = self.tools.get_account_status(target)
        try:
            return AccountState(raw) if raw else None
        except ValueError:
            return None

    def _log(self, event: EventType, payload: dict) -> None:
        try:
            self.audit.append(event, "executor", payload, self.policy.policy_hash)
        except AuditWriteError:
            pass


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)
