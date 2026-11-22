"""Typed data contracts for S.H.I.E.L.D.

Every model is ``frozen=True, extra="forbid"``. Two consequences the design
leans on:

* **Frozen** - a work order, a trust label or an approval cannot be edited
  after it is issued. An agent that wants more power has to get a *new* object
  past the gateway, and the gateway will not issue one.
* **extra="forbid"** - an agent cannot smuggle an unexpected field (say
  ``"budget_override"``) through a schema-validated boundary. Malformed output
  is rejected rather than partially honoured.

No free-text fields appear in ``EvidencePack``, ``Claim`` or ``Proposal``:
agents speak in ids and enums, and humans read raw records through
``record_refs`` in the UI. Free text is the carrier for prompt injection, so it
never travels on the evidence path.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from core.canonical import hash_obj

# --------------------------------------------------------------------------
# Base
# --------------------------------------------------------------------------


class Frozen(BaseModel):
    """Shared config: immutable, closed to unknown fields, enum values on dump."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


class Tier(str, Enum):
    READ = "read"
    WRITE = "write"


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class CaseStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"


class StopReason(str, Enum):
    COMPLETED = "COMPLETED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TIMEOUT = "TIMEOUT"
    DENIED = "DENIED"
    TOOL_FAILURE = "TOOL_FAILURE"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    UNRESOLVED_CONFLICT = "UNRESOLVED_CONFLICT"
    THRESHOLD_NOT_MET = "THRESHOLD_NOT_MET"
    UNTRUSTED_TARGET = "UNTRUSTED_TARGET"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_MISMATCH = "APPROVAL_MISMATCH"
    DUPLICATE_ACTION = "DUPLICATE_ACTION"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    POLICY_TAMPERED = "POLICY_TAMPERED"
    ESCALATED = "ESCALATED"
    STATE_CHANGED_SINCE_APPROVAL = "STATE_CHANGED_SINCE_APPROVAL"
    # Optional checks (Phase 6)
    INSUFFICIENT_INDEPENDENT_SOURCES = "INSUFFICIENT_INDEPENDENT_SOURCES"
    MISSED_ACTION = "MISSED_ACTION"


class EventType(str, Enum):
    ORDER = "ORDER"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    DENIAL = "DENIAL"
    DECISION = "DECISION"
    PROPOSAL = "PROPOSAL"
    APPROVAL = "APPROVAL"
    ACTION = "ACTION"
    STOP = "STOP"
    ALERT = "ALERT"


class DenialReason(str, Enum):
    """Why the gateway refused a call. Logged verbatim on every denial."""

    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    CALLER_MISMATCH = "CALLER_MISMATCH"
    ORDER_HASH_INVALID = "ORDER_HASH_INVALID"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    TOOL_FORBIDDEN = "TOOL_FORBIDDEN"
    WRITE_TOOL_DENIED = "WRITE_TOOL_DENIED"
    ARGS_INVALID = "ARGS_INVALID"
    TARGET_NOT_PERMITTED = "TARGET_NOT_PERMITTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    POLICY_TAMPERED = "POLICY_TAMPERED"
    AUDIT_WRITE_FAILED = "AUDIT_WRITE_FAILED"
    TOOL_FAILURE = "TOOL_FAILURE"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    PLAN_LOCKED = "PLAN_LOCKED"
    CASE_ESCALATED = "CASE_ESCALATED"


class EscalationTrigger(str, Enum):
    UNRESOLVED_CONFLICT = "UNRESOLVED_CONFLICT"
    MALFORMED_OUTPUT_REPEATED = "MALFORMED_OUTPUT_REPEATED"
    UNEXPECTED_ERROR = "UNEXPECTED_ERROR"
    POLICY_TAMPERED = "POLICY_TAMPERED"


class ClaimPredicate(str, Enum):
    """The closed set of things a worker may assert.

    A fixed vocabulary is what makes ``core/compare.py`` able to detect
    disagreement in code: two workers either assert the same (subject,
    predicate) pair or they do not. Free-text findings could not be compared
    deterministically, and would reopen the injection channel.
    """

    INBOUND_FROM_NEW_ACCOUNTS_ABOVE_MIN = "INBOUND_FROM_NEW_ACCOUNTS_ABOVE_MIN"
    TOTAL_INBOUND_ABOVE_MIN = "TOTAL_INBOUND_ABOVE_MIN"
    RAPID_INBOUND_TO_OUTBOUND = "RAPID_INBOUND_TO_OUTBOUND"
    COUNTERPARTY_RING_SUSPECTED = "COUNTERPARTY_RING_SUSPECTED"
    PRIOR_FRAUD_REPORT_IN_NOTES = "PRIOR_FRAUD_REPORT_IN_NOTES"
    ACTIVITY_CONSISTENT_WITH_HISTORY = "ACTIVITY_CONSISTENT_WITH_HISTORY"
    SUBJECT_SHOWS_MULE_PATTERN = "SUBJECT_SHOWS_MULE_PATTERN"


class MissingEvidenceCode(str, Enum):
    """What a PARTIAL pack could not obtain.

    An enum rather than free text: ``missing`` is read by the case report and
    shown to a human, and a free-text field on the evidence path is an
    injection carrier.
    """

    TRANSACTION_HISTORY = "TRANSACTION_HISTORY"
    CASE_NOTES = "CASE_NOTES"
    COUNTERPARTY_PROFILE = "COUNTERPARTY_PROFILE"
    ACCOUNT_METADATA = "ACCOUNT_METADATA"
    OUTBOUND_TRACE = "OUTBOUND_TRACE"


class AssumptionCode(str, Enum):
    TRANSACTION_WINDOW_MAY_BE_INCOMPLETE = "TRANSACTION_WINDOW_MAY_BE_INCOMPLETE"
    NOTES_MAY_BE_INCOMPLETE = "NOTES_MAY_BE_INCOMPLETE"
    COUNTERPARTY_AGE_FROM_SINGLE_SOURCE = "COUNTERPARTY_AGE_FROM_SINGLE_SOURCE"
    DATA_TRUNCATED_BY_BUDGET = "DATA_TRUNCATED_BY_BUDGET"
    DATA_TRUNCATED_BY_TOOL_FAILURE = "DATA_TRUNCATED_BY_TOOL_FAILURE"
    NOTE_CONTENT_IS_UNTRUSTED = "NOTE_CONTENT_IS_UNTRUSTED"


class ActionName(str, Enum):
    FREEZE = "FREEZE"
    UNFREEZE = "UNFREEZE"
    NONE = "NONE"


class AccountState(str, Enum):
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"


class IdempotencyState(str, Enum):
    INTENT = "INTENT"
    EXECUTED = "EXECUTED"
    CONFIRMED = "CONFIRMED"


Confidence = Literal["LOW", "MEDIUM", "HIGH"]
SourceSystem = Literal["transactions_db", "notes_store", "accounts_db"]


# --------------------------------------------------------------------------
# Budget
# --------------------------------------------------------------------------


class Budget(Frozen):
    calls: int = Field(ge=0)
    tokens: int = Field(ge=0)
    seconds: int = Field(ge=0)


class BudgetUsage(Frozen):
    calls: int = 0
    tokens: int = 0
    seconds: float = 0.0


# --------------------------------------------------------------------------
# Work orders
# --------------------------------------------------------------------------


class WorkOrder(Frozen):
    """An immutable grant of authority to one worker.

    ``order_hash`` covers every other field. The gateway recomputes it on every
    call, so an agent that edits its own copy of the order - to add a tool or
    raise a budget - produces a hash that no longer matches and is denied.
    """

    order_id: str
    case_id: str
    worker_role: str
    goal: str
    success_criteria: list[str]
    allowed_tools: list[str]
    forbidden_actions: list[str]
    budget: Budget
    required_evidence: list[str]
    stop_conditions: list[str]
    target_account: str
    policy_hash: str
    issued_at: datetime
    order_hash: str

    # -- hashing -----------------------------------------------------------

    @staticmethod
    def _payload(data: dict) -> dict:
        return {k: v for k, v in data.items() if k != "order_hash"}

    @classmethod
    def new(cls, **fields) -> "WorkOrder":
        """Build an order and stamp it with the hash of its own contents."""
        fields.setdefault("issued_at", utcnow())
        probe = cls.model_construct(**fields, order_hash="")
        payload = cls._payload(probe.model_dump(mode="json"))
        return cls(**fields, order_hash=hash_obj(payload))

    def expected_hash(self) -> str:
        return hash_obj(self._payload(self.model_dump(mode="json")))

    def hash_is_valid(self) -> bool:
        return self.order_hash == self.expected_hash()


# --------------------------------------------------------------------------
# Trust-labelled data
# --------------------------------------------------------------------------


class LabeledValue(Frozen):
    """One field of one tool result, with the trust label code gave it.

    ``trust`` is set exactly once, by the gateway, from
    ``policy.tools.<tool>.field_trust`` - never by an LLM, and never upgraded
    later. ``source_record`` ("txn:TXN-0042.to_account") is the identity the
    provenance ledger keys on, so the same field read twice gets the same
    label and a value copied into untrusted text cannot acquire a new one.
    """

    value: str | int | float | bool
    source_tool: str
    source_record: str
    trust: Trust
    raw_hash: str


class LabeledRecord(Frozen):
    """One row of tool output, every field labelled."""

    record_id: str  # "txn:TXN-0042"
    fields: dict[str, LabeledValue]


# --------------------------------------------------------------------------
# Gateway results
# --------------------------------------------------------------------------


class ToolResult(Frozen):
    call_id: str
    tool: str
    raw_hash: str
    records: list[LabeledRecord]
    log_entry_id: str
    elapsed_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return True


class GatewayDenial(Frozen):
    call_id: str
    tool: str
    reason: DenialReason
    detail: str
    log_entry_id: str
    stop_reason: StopReason = StopReason.DENIED
    # True when a WRITE may have landed but the response was lost. The caller
    # must read back before deciding anything - it must not assume failure.
    response_unknown: bool = False

    @property
    def ok(self) -> bool:
        return False


GatewayOutcome = ToolResult | GatewayDenial


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


class EvidenceItem(Frozen):
    """A pointer to raw tool output - never a copy of it.

    ``record_refs`` are verified to exist in the stored raw output keyed by
    ``raw_hash``, so an agent cannot cite evidence it never read.
    """

    item_id: str
    source_tool: str
    source_system: SourceSystem
    raw_hash: str
    record_refs: list[str]
    trust: Trust


class Claim(Frozen):
    claim_id: str
    subject: str
    predicate: ClaimPredicate
    value: bool
    confidence: Confidence
    evidence_for: list[str] = Field(default_factory=list)
    evidence_against: list[str] = Field(default_factory=list)


class EvidencePack(Frozen):
    order_id: str
    order_hash: str
    claims: list[Claim] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    assumptions: list[AssumptionCode] = Field(default_factory=list)
    tool_log: list[str] = Field(default_factory=list)
    status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    stop_reason: StopReason
    missing: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


class Verdict(str, Enum):
    AGREE = "AGREE"
    CONFLICT = "CONFLICT"
    SINGLE = "SINGLE"


class ClaimRef(Frozen):
    claim_id: str
    order_id: str
    worker_role: str
    value: bool
    confidence: Confidence
    evidence_item_ids: list[str]
    trusted_sources: list[str]  # distinct source_system values, TRUSTED items only


class ClaimGroup(Frozen):
    subject: str
    predicate: ClaimPredicate
    verdict: Verdict
    asserted: list[ClaimRef]  # claims with value=True
    denied: list[ClaimRef]  # claims with value=False
    independent_trusted_sources: int


class ComparisonReport(Frozen):
    groups: list[ClaimGroup]

    @property
    def conflicts(self) -> list[ClaimGroup]:
        return [g for g in self.groups if g.verdict is Verdict.CONFLICT]


# --------------------------------------------------------------------------
# Proposal, approval, action
# --------------------------------------------------------------------------


class Proposal(Frozen):
    proposal_id: str
    case_id: str
    action: ActionName
    target: LabeledValue
    supporting_claims: list[str] = Field(default_factory=list)
    policy_hash: str


class ApprovalRequest(Frozen):
    """Exactly what the human is shown, and exactly what they bind to."""

    action_hash: str
    case_id: str
    action: ActionName
    target: str
    account_state: AccountState
    policy_hash: str
    evidence_raw_hashes: list[str]
    ttl_seconds: int


class ApprovalRecord(Frozen):
    approval_id: str
    action_hash: str
    approver: str
    account_state_at_approval: AccountState
    decision: Literal["APPROVED", "REJECTED"]
    issued_at: datetime
    expires_at: datetime
    used: bool = False


class ActionOutcome(Frozen):
    """What the executor did, or why it refused."""

    case_id: str
    action: ActionName
    target: str | None
    executed: bool
    stop_reason: StopReason
    action_hash: str | None = None
    approval_id: str | None = None
    idempotency_state: IdempotencyState | None = None
    detail: str = ""


# --------------------------------------------------------------------------
# Case-level reporting
# --------------------------------------------------------------------------


class WorkerSummary(Frozen):
    order_id: str
    worker_role: str
    status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    stop_reason: StopReason
    missing: list[str]
    usage: BudgetUsage


class EscalationNotice(Frozen):
    trigger: EscalationTrigger
    log_entry_id: str
    detail: str


class CaseReport(Frozen):
    case_id: str
    scenario_id: str | None
    status: CaseStatus
    policy_hash: str
    workers: list[WorkerSummary]
    packs: list[EvidencePack]
    comparison: ComparisonReport
    proposal: Proposal | None
    action: ActionOutcome | None
    escalations: list[EscalationNotice]
    missing: list[str]
    ai_summary: str | None  # shown last in the UI, never read by the executor
    started_at: datetime
    finished_at: datetime
