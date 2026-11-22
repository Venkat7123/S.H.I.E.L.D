"""Approval binding: one action, one state, one use, and an expiry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.approval import (
    ApprovalGate,
    ApprovalPresentation,
    compute_action_hash,
)
from core.models import AccountState, ActionName, ApprovalRequest, StopReason


def _request(
    *, state: AccountState = AccountState.ACTIVE, target: str = "ACCT-0001", evidence=("h1", "h2")
) -> ApprovalRequest:
    action_hash = compute_action_hash(
        case_id="CASE-001",
        action=ActionName.FREEZE,
        target=target,
        evidence_raw_hashes=list(evidence),
        policy_hash="p" * 64,
        account_state=state,
    )
    return ApprovalRequest(
        action_hash=action_hash,
        case_id="CASE-001",
        action=ActionName.FREEZE,
        target=target,
        account_state=state,
        policy_hash="p" * 64,
        evidence_raw_hashes=list(evidence),
        ttl_seconds=600,
    )


def _presentation(req: ApprovalRequest) -> ApprovalPresentation:
    return ApprovalPresentation(
        request=req, trusted_evidence=[], disagreements=[], untrusted_items=[]
    )


def approve(_p):
    return "APPROVED", "analyst@bank"


def reject(_p):
    return "REJECTED", "analyst@bank"


def test_action_hash_is_order_independent_over_evidence() -> None:
    a = compute_action_hash(
        case_id="C", action="FREEZE", target="ACCT-0001",
        evidence_raw_hashes=["b", "a"], policy_hash="p", account_state="ACTIVE",
    )
    b = compute_action_hash(
        case_id="C", action="FREEZE", target="ACCT-0001",
        evidence_raw_hashes=["a", "b", "a"], policy_hash="p", account_state="ACTIVE",
    )
    assert a == b


def test_account_state_is_part_of_the_action_hash() -> None:
    active = _request(state=AccountState.ACTIVE).action_hash
    frozen = _request(state=AccountState.FROZEN).action_hash
    assert active != frozen


def test_changing_the_target_changes_the_hash() -> None:
    assert _request(target="ACCT-0001").action_hash != _request(target="ACCT-0999").action_hash


def test_changing_the_evidence_changes_the_hash() -> None:
    assert _request(evidence=("h1",)).action_hash != _request(evidence=("h1", "h2")).action_hash


def test_an_approval_authorises_exactly_one_action(db_path) -> None:
    gate = ApprovalGate(db_path)
    req = _request()
    record = gate.request(_presentation(req), approve, ttl_seconds=600)
    other = _request(target="ACCT-0999")
    check = gate.consume(record.approval_id, other.action_hash)
    assert not check.ok
    assert check.stop_reason is StopReason.APPROVAL_MISMATCH
    gate.close()


def test_an_approval_is_single_use(db_path) -> None:
    gate = ApprovalGate(db_path)
    req = _request()
    record = gate.request(_presentation(req), approve, ttl_seconds=600)
    assert gate.consume(record.approval_id, req.action_hash).ok
    replay = gate.consume(record.approval_id, req.action_hash)
    assert not replay.ok
    assert replay.stop_reason is StopReason.APPROVAL_MISMATCH
    assert "single-use" in replay.detail
    gate.close()


def test_an_expired_approval_is_refused(db_path) -> None:
    clock = {"now": datetime(2026, 3, 1, tzinfo=timezone.utc)}
    gate = ApprovalGate(db_path, now=lambda: clock["now"])
    req = _request()
    record = gate.request(_presentation(req), approve, ttl_seconds=600)
    clock["now"] = clock["now"] + timedelta(seconds=601)
    check = gate.consume(record.approval_id, req.action_hash)
    assert not check.ok
    assert check.stop_reason is StopReason.APPROVAL_EXPIRED
    gate.close()


def test_an_approval_inside_its_ttl_is_accepted(db_path) -> None:
    clock = {"now": datetime(2026, 3, 1, tzinfo=timezone.utc)}
    gate = ApprovalGate(db_path, now=lambda: clock["now"])
    req = _request()
    record = gate.request(_presentation(req), approve, ttl_seconds=600)
    clock["now"] = clock["now"] + timedelta(seconds=599)
    assert gate.consume(record.approval_id, req.action_hash).ok
    gate.close()


def test_a_rejection_cannot_be_redeemed(db_path) -> None:
    gate = ApprovalGate(db_path)
    req = _request()
    record = gate.request(_presentation(req), reject, ttl_seconds=600)
    check = gate.consume(record.approval_id, req.action_hash)
    assert not check.ok
    assert check.stop_reason is StopReason.APPROVAL_REJECTED
    gate.close()


def test_an_unknown_approval_id_is_refused(db_path) -> None:
    gate = ApprovalGate(db_path)
    check = gate.consume("APPR-nonexistent", "x" * 64)
    assert not check.ok
    assert check.stop_reason is StopReason.APPROVAL_MISMATCH
    gate.close()


def test_a_decider_returning_nonsense_is_treated_as_rejection(db_path) -> None:
    """Fail closed: anything that is not exactly APPROVED is a refusal."""
    gate = ApprovalGate(db_path)
    req = _request()
    record = gate.request(_presentation(req), lambda _p: ("maybe", "x"), ttl_seconds=600)
    assert record.decision == "REJECTED"
    gate.close()
