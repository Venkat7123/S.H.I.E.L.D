"""Structured output schemas - the only shapes an LLM may return.

Every field is an id, an enum or a number. There is exactly one free-text
field in the whole agent surface, :attr:`ProposalDraft.summary`, and it is
stored separately, shown last, labelled "AI-written - not evidence", and never
read by the executor.

That constraint does most of the security work at this boundary. A model that
can only emit ``ClaimPredicate.RAPID_INBOUND_TO_OUTBOUND`` and a list of
evidence ids cannot smuggle an instruction, a fabricated quote or a laundered
account number through the evidence path, however thoroughly it has been
hijacked by something it read.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from core.models import (
    AssumptionCode,
    ClaimPredicate,
    Confidence,
    MissingEvidenceCode,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReasonCode(str, Enum):
    """Why the worker wants another call, or is stopping. No free text."""

    NEED_TRANSACTIONS = "NEED_TRANSACTIONS"
    NEED_NOTES = "NEED_NOTES"
    NEED_COUNTERPARTY_HISTORY = "NEED_COUNTERPARTY_HISTORY"
    SUFFICIENT_EVIDENCE = "SUFFICIENT_EVIDENCE"
    BUDGET_LOW = "BUDGET_LOW"
    BLOCKED = "BLOCKED"


class NextCall(_Strict):
    """One step of a worker's loop."""

    action: Literal["call", "finish"]
    reason: ReasonCode
    tool: str | None = None
    args: dict[str, str | int] = Field(default_factory=dict)


class ClaimDraft(_Strict):
    predicate: ClaimPredicate
    subject: str
    value: bool
    confidence: Confidence
    evidence_for: list[str] = Field(default_factory=list)
    evidence_against: list[str] = Field(default_factory=list)


class PackDraft(_Strict):
    """What the worker concluded. Claims cite evidence ids code minted."""

    claims: list[ClaimDraft] = Field(default_factory=list)
    assumptions: list[AssumptionCode] = Field(default_factory=list)
    status: Literal["COMPLETE", "PARTIAL", "FAILED"] = "COMPLETE"
    missing: list[MissingEvidenceCode] = Field(default_factory=list)


class PlanDraft(_Strict):
    """The supervisor's plan: roles chosen from a fixed menu, and a window.

    The supervisor cannot invent a role, a tool or a budget here. It picks from
    a menu; code builds the orders.
    """

    roles: list[str] = Field(min_length=1)
    days: int = Field(ge=1, le=90)


class ProposalDraft(_Strict):
    """The supervisor's recommendation.

    ``target`` is a plain account id. Code looks it up in the provenance ledger
    to find out what trust that value actually carries - the supervisor does not
    get to say.

    ``target_trust_override`` exists so a *compromised* supervisor can be
    simulated honestly: the supervisor is untrusted-zone code and is free to
    assert anything. Scenario A9 uses it to forge a TRUSTED label, and the
    executor still refuses, because it re-derives trust from storage.
    """

    action: Literal["FREEZE", "UNFREEZE", "NONE"]
    target: str | None = None
    supporting_claims: list[str] = Field(default_factory=list)
    target_trust_override: Literal["trusted", "untrusted"] | None = None
    summary: str | None = None
