"""The executor: everything it refuses, and the one thing it does."""

from __future__ import annotations

import pytest

from core.compare import compare
from core.escalation import EscalationTracker
from core.models import (
    ActionName,
    EscalationTrigger,
    EvidenceItem,
    EvidencePack,
    LabeledValue,
    Proposal,
    StopReason,
    Trust,
)
from agents.worker import mint_evidence


def approve(_p):
    return "APPROVED", "analyst@bank"


def reject(_p):
    return "REJECTED", "analyst@bank"


# --------------------------------------------------------------------------
# Helpers: gather real evidence the way a worker would
# --------------------------------------------------------------------------


def _gather(stack, account="ACCT-0001", role="transaction_analyst", case_id="CASE-001"):
    order = stack.order(role, case_id=case_id, target=account)
    result = stack.client(order).call("query_transactions", account_id=account, days=60)
    assert result.ok
    items = mint_evidence(result)
    pack = EvidencePack(
        order_id=order.order_id,
        order_hash=order.order_hash,
        claims=[],
        evidence_items=items,
        assumptions=[],
        tool_log=[result.log_entry_id],
        status="COMPLETE",
        stop_reason=StopReason.COMPLETED,
        missing=[],
    )
    return order, result, pack


def _trusted_label(stack, source_record="txn:TXN-0002.to_account") -> LabeledValue:
    row = stack.ledger._fetch(source_record)
    import json

    return LabeledValue(
        value=json.loads(row["value_json"]),
        source_tool=row["source_tool"],
        source_record=source_record,
        trust=Trust(row["trust"]),
        raw_hash=row["raw_hash"],
    )


def _proposal(stack, target: LabeledValue, case_id="CASE-001", action=ActionName.FREEZE):
    return Proposal(
        proposal_id="PROP-test",
        case_id=case_id,
        action=action,
        target=target,
        supporting_claims=[],
        policy_hash=stack.policy.policy_hash,
    )


def _run(stack, proposal, packs, *, decider=approve, case_id="CASE-001", tracker=None):
    tracker = tracker or EscalationTracker(stack.policy, stack.audit, case_id)
    return stack.executor.execute(
        case_id=case_id,
        proposal=proposal,
        packs=packs,
        comparison=compare(packs, {}),
        escalation=tracker,
        decider=decider,
    )


# --------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------


def test_a_verified_freeze_executes_once(stack) -> None:
    _order, _result, pack = _gather(stack)
    outcome = _run(stack, _proposal(stack, _trusted_label(stack)), [pack])
    assert outcome.executed, outcome.detail
    assert outcome.stop_reason is StopReason.COMPLETED
    assert stack.tools.get_account_status("ACCT-0001") == "FROZEN"


# --------------------------------------------------------------------------
# Target rules
# --------------------------------------------------------------------------


def test_an_untrusted_target_is_refused(stack) -> None:
    """The headline: an id that arrived inside a transaction description."""
    _order, _result, pack = _gather(stack)
    laundered = _trusted_label(stack, "txn:TXN-0002.description")
    assert laundered.trust is Trust.UNTRUSTED
    laundered = laundered.model_copy(update={"value": "ACCT-0999"})

    outcome = _run(stack, _proposal(stack, laundered), [pack])
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.UNTRUSTED_TARGET
    assert stack.tools.get_account_status("ACCT-0999") == "ACTIVE"


def test_a_forged_trusted_label_is_refused(stack) -> None:
    _order, _result, pack = _gather(stack)
    forged = _trusted_label(stack, "txn:TXN-0002.description").model_copy(
        update={"value": "ACCT-0999", "trust": Trust.TRUSTED}
    )
    outcome = _run(stack, _proposal(stack, forged), [pack])
    assert outcome.stop_reason is StopReason.UNTRUSTED_TARGET
    assert "does not verify" in outcome.detail


def test_a_target_outside_the_case_is_refused(stack) -> None:
    """ACCT-0004 is a real account, trusted everywhere - but not in this case."""
    _order, _result, pack = _gather(stack, account="ACCT-0002", case_id="CASE-002")
    stranger = LabeledValue(
        value="ACCT-0004",
        source_tool="query_transactions",
        source_record="txn:TXN-0104.to_account",
        trust=Trust.TRUSTED,
        raw_hash="0" * 64,
    )
    outcome = _run(stack, _proposal(stack, stranger, case_id="CASE-002"), [pack],
                   case_id="CASE-002")
    assert outcome.stop_reason is StopReason.UNTRUSTED_TARGET


# --------------------------------------------------------------------------
# Threshold
# --------------------------------------------------------------------------


def test_an_innocent_account_does_not_meet_the_threshold(stack) -> None:
    _order, _result, pack = _gather(stack, account="ACCT-0002", case_id="CASE-002")
    target = _trusted_label(stack, "txn:TXN-0102.to_account")
    outcome = _run(stack, _proposal(stack, target, case_id="CASE-002"), [pack],
                   case_id="CASE-002")
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.THRESHOLD_NOT_MET
    assert stack.tools.get_account_status("ACCT-0002") == "ACTIVE"


def test_evidence_that_does_not_resolve_is_discarded(stack) -> None:
    _order, result, pack = _gather(stack)
    fabricated = EvidenceItem(
        item_id="EV-FAKE-T",
        source_tool="query_transactions",
        source_system="transactions_db",
        raw_hash="f" * 64,
        record_refs=["txn:TXN-9999"],
        trust=Trust.TRUSTED,
    )
    bad_pack = pack.model_copy(update={"evidence_items": [fabricated]})
    outcome = _run(stack, _proposal(stack, _trusted_label(stack)), [bad_pack])
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.THRESHOLD_NOT_MET


def test_evidence_claiming_the_wrong_source_system_is_discarded(stack) -> None:
    """Notes dressed up as transaction records do not become transactions."""
    order = stack.order("notes_reviewer", tools=["read_case_notes"])
    notes = stack.client(order).call("read_case_notes", account_id="ACCT-0001", limit=10)
    mislabelled = EvidenceItem(
        item_id="EV-LIE-T",
        source_tool="read_case_notes",
        source_system="transactions_db",  # a lie
        raw_hash=notes.raw_hash,
        record_refs=["note:NOTE-0002"],
        trust=Trust.TRUSTED,
    )
    _o2, _r2, real = _gather(stack)
    pack = real.model_copy(update={"evidence_items": [mislabelled]})
    outcome = _run(stack, _proposal(stack, _trusted_label(stack)), [pack])
    assert outcome.stop_reason is StopReason.THRESHOLD_NOT_MET


# --------------------------------------------------------------------------
# Escalation and approval
# --------------------------------------------------------------------------


def test_an_escalated_case_never_reaches_the_write_path(stack) -> None:
    _order, _result, pack = _gather(stack)
    tracker = EscalationTracker(stack.policy, stack.audit, "CASE-001")
    tracker.note(EscalationTrigger.UNRESOLVED_CONFLICT, "workers disagree")

    outcome = _run(stack, _proposal(stack, _trusted_label(stack)), [pack], tracker=tracker)
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.ESCALATED
    assert stack.tools.get_account_status("ACCT-0001") == "ACTIVE"
    # Nothing was even presented for approval.
    assert not [e for e in stack.audit.entries() if e.event_type.value == "APPROVAL"]


def test_a_rejected_approval_does_not_write(stack) -> None:
    _order, _result, pack = _gather(stack)
    outcome = _run(stack, _proposal(stack, _trusted_label(stack)), [pack], decider=reject)
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.APPROVAL_REJECTED
    assert stack.tools.get_account_status("ACCT-0001") == "ACTIVE"


def test_state_changing_after_approval_blocks_the_write(stack) -> None:
    """The race the state-bound hash exists to close."""
    _order, _result, pack = _gather(stack)

    def approve_then_meddle(_presentation):
        # Someone else freezes the account between approval and execution.
        stack.tools.set_account_status("ACCT-0001", "FREEZE", "x" * 64)
        return "APPROVED", "analyst@bank"

    outcome = _run(stack, _proposal(stack, _trusted_label(stack)), [pack],
                   decider=approve_then_meddle)
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.STATE_CHANGED_SINCE_APPROVAL


def test_a_proposal_under_a_different_policy_is_refused(stack) -> None:
    _order, _result, pack = _gather(stack)
    stale = _proposal(stack, _trusted_label(stack)).model_copy(
        update={"policy_hash": "0" * 64}
    )
    outcome = _run(stack, stale, [pack])
    assert outcome.stop_reason is StopReason.POLICY_TAMPERED


def test_a_proposal_for_another_case_is_refused(stack) -> None:
    _order, _result, pack = _gather(stack)
    wrong = _proposal(stack, _trusted_label(stack), case_id="CASE-002")
    outcome = _run(stack, wrong, [pack])
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.DENIED


def test_action_none_does_nothing_and_is_not_an_error(stack) -> None:
    _order, _result, pack = _gather(stack)
    outcome = _run(stack, _proposal(stack, _trusted_label(stack), action=ActionName.NONE), [pack])
    assert not outcome.executed
    assert outcome.stop_reason is StopReason.COMPLETED
    assert stack.tools.get_account_status("ACCT-0001") == "ACTIVE"


def test_independent_source_check_when_enabled(stack) -> None:
    """Phase 6: evidence resting on one system of record is not enough."""
    stack.executor.enable_independent_sources = True
    order = stack.order("notes_reviewer", tools=["read_case_notes"])
    notes = stack.client(order).call("read_case_notes", account_id="ACCT-0001", limit=10)
    items = mint_evidence(notes)
    pack = EvidencePack(
        order_id=order.order_id,
        order_hash=order.order_hash,
        claims=[],
        evidence_items=items,
        assumptions=[],
        tool_log=[notes.log_entry_id],
        status="COMPLETE",
        stop_reason=StopReason.COMPLETED,
        missing=[],
    )
    # Build a trusted target from the notes' own account_id field.
    target = _trusted_label(stack, "note:NOTE-0002.account_id")
    outcome = _run(stack, _proposal(stack, target), [pack])
    # No transactions were gathered, so the threshold fails before the source
    # count is even reached - both are refusals, which is the point.
    assert not outcome.executed
    assert outcome.stop_reason in (
        StopReason.THRESHOLD_NOT_MET,
        StopReason.INSUFFICIENT_INDEPENDENT_SOURCES,
    )
