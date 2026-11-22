"""Canonicalisation, models, policy loading, budget, comparison, escalation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.audit_log import AuditEntry
from core.budget import BudgetMeter
from core.canonical import canonical_json, canonicalize_account, hash_obj
from core.compare import compare, summarise
from core.escalation import EscalationTracker, derive_triggers
from core.models import (
    Budget,
    Claim,
    ClaimPredicate,
    EscalationTrigger,
    EventType,
    EvidenceItem,
    EvidencePack,
    StopReason,
    Trust,
    Verdict,
    WorkOrder,
)
from policy.loader import PolicyError, load_policy

# --------------------------------------------------------------------------
# Canonicalisation
# --------------------------------------------------------------------------


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert hash_obj({"b": [1, 2], "a": "x"}) == hash_obj({"a": "x", "b": [1, 2]})


def test_canonical_json_is_stable_across_nesting_order() -> None:
    a = {"outer": {"z": 1, "a": 2}, "list": [{"k": 1}, {"j": 2}]}
    b = {"list": [{"k": 1}, {"j": 2}], "outer": {"a": 2, "z": 1}}
    assert hash_obj(a) == hash_obj(b)


@pytest.mark.parametrize(
    "spelling",
    ["acct-0001", "ACCT-0001", " ACCT-0001 ", "ACCT‑0001", "ACCT–0001", "ＡＣＣＴ－０００１"],
)
def test_account_spellings_fold_to_one(spelling: str) -> None:
    assert canonicalize_account(spelling) == "ACCT-0001"


def test_different_accounts_do_not_fold_together() -> None:
    assert canonicalize_account("ACCT-0001") != canonicalize_account("ACCT-0002")


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


def _order(**overrides) -> WorkOrder:
    fields = dict(
        order_id="ORD-1",
        case_id="CASE-001",
        worker_role="transaction_analyst",
        goal="investigate",
        success_criteria=["a"],
        allowed_tools=["query_transactions"],
        forbidden_actions=["set_account_status"],
        budget=Budget(calls=10, tokens=20000, seconds=120),
        required_evidence=["txns"],
        stop_conditions=["budget"],
        target_account="ACCT-0001",
        policy_hash="p" * 64,
    )
    fields.update(overrides)
    return WorkOrder.new(**fields)


def test_a_work_order_is_frozen() -> None:
    order = _order()
    with pytest.raises(ValidationError):
        order.allowed_tools = ["set_account_status"]  # type: ignore[misc]


def test_order_hash_covers_every_field() -> None:
    order = _order()
    assert order.hash_is_valid()
    for change in (
        {"allowed_tools": ["set_account_status"]},
        {"budget": Budget(calls=999, tokens=999, seconds=999)},
        {"target_account": "ACCT-0999"},
        {"forbidden_actions": []},
        {"worker_role": "executor"},
    ):
        assert not order.model_copy(update=change).hash_is_valid(), change


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Claim(
            claim_id="C1",
            subject="ACCT-0001",
            predicate=ClaimPredicate.SUBJECT_SHOWS_MULE_PATTERN,
            value=True,
            confidence="HIGH",
            budget_override=999,  # type: ignore[call-arg]
        )


def test_a_claim_cannot_carry_free_text() -> None:
    with pytest.raises(ValidationError):
        Claim(
            claim_id="C1",
            subject="ACCT-0001",
            predicate="this account is definitely fraudulent",  # type: ignore[arg-type]
            value=True,
            confidence="HIGH",
        )


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


def test_a_policy_with_unknown_keys_is_rejected(tmp_path) -> None:
    src = (tmp_path / "p.yaml")
    src.write_text(
        (
            "version: '1'\ndefault: deny\n"
            "tools: {}\nroles: {}\n"
            "global_budget: {calls: 1, tokens: 1, seconds: 1}\n"
            "actions: {}\n"
            "idempotency: {key_fields: [case_id]}\n"
            "trust: {origin_rule: first_entry}\n"
            "escalation: {triggers: []}\n"
            "backdoor: true\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_policy(src)


def test_a_policy_granting_a_write_tool_to_a_role_is_rejected(tmp_path, policy_file) -> None:
    text = policy_file.read_text(encoding="utf-8")
    text = text.replace(
        "    tools: [query_transactions]\n    budget: {calls: 10",
        "    tools: [query_transactions, set_account_status]\n    budget: {calls: 10",
        1,
    )
    bad = tmp_path / "bad.yaml"
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError, match="write tool"):
        load_policy(bad)


def test_a_missing_policy_file_raises(tmp_path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.yaml")


def test_default_deny_applies_to_unlisted_tools(policy) -> None:
    assert not policy.may_call("anything_at_all", "transaction_analyst")
    assert not policy.may_call("anything_at_all", "executor")


def test_the_policy_hash_survives_a_line_ending_change(tmp_path, policy_file) -> None:
    """A CRLF checkout must not look like a tampered policy.

    `policy_hash` is taken over the file's bytes and re-checked before every
    tool call. Without normalisation, cloning the repo on Windows would rewrite
    every line ending and the gateway would deny every call with
    POLICY_TAMPERED on a completely untouched file.
    """
    lf = policy_file.read_bytes().replace(b"\r\n", b"\n")
    crlf_file = tmp_path / "policy_crlf.yaml"
    crlf_file.write_bytes(lf.replace(b"\n", b"\r\n"))
    lf_file = tmp_path / "policy_lf.yaml"
    lf_file.write_bytes(lf)

    assert b"\r\n" in crlf_file.read_bytes()  # the fixture really is CRLF
    assert load_policy(crlf_file).policy_hash == load_policy(lf_file).policy_hash


def test_the_policy_hash_changes_when_the_file_changes(policy_file) -> None:
    before = load_policy(policy_file).policy_hash
    policy_file.write_text(
        policy_file.read_text(encoding="utf-8").replace("calls: 10", "calls: 11"),
        encoding="utf-8",
    )
    assert load_policy(policy_file).policy_hash != before


# --------------------------------------------------------------------------
# Budget
# --------------------------------------------------------------------------


def test_the_tighter_of_worker_and_global_budget_wins() -> None:
    meter = BudgetMeter(Budget(calls=3, tokens=1000, seconds=60))
    meter.register("w", Budget(calls=10, tokens=1000, seconds=60))
    assert all(meter.reserve("w").ok for _ in range(3))
    decision = meter.reserve("w")
    assert not decision.ok
    assert decision.scope == "__global__"


def test_token_budget_is_enforced() -> None:
    meter = BudgetMeter(Budget(calls=100, tokens=1000, seconds=60))
    meter.register("w", Budget(calls=100, tokens=500, seconds=60))
    assert meter.reserve("w", calls=0, tokens=400).ok
    assert not meter.reserve("w", calls=0, tokens=200).ok


def test_an_unregistered_scope_gets_nothing() -> None:
    meter = BudgetMeter(Budget(calls=100, tokens=1000, seconds=60))
    assert not meter.reserve("ghost").ok


def test_reconcile_charges_token_overspend() -> None:
    meter = BudgetMeter(Budget(calls=10, tokens=1000, seconds=60))
    meter.register("w", Budget(calls=10, tokens=1000, seconds=60))
    decision = meter.reserve("w", tokens=10)
    meter.reconcile(decision.reservation, tokens_used=900, seconds_used=0.1)
    assert meter.usage("w").tokens == 900


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


def _pack(order_id: str, *claims: Claim, items=()) -> EvidencePack:
    return EvidencePack(
        order_id=order_id,
        order_hash="h" * 64,
        claims=list(claims),
        evidence_items=list(items),
        assumptions=[],
        tool_log=[],
        status="COMPLETE",
        stop_reason=StopReason.COMPLETED,
        missing=[],
    )


def _claim(cid: str, value: bool, items=("EV-1",)) -> Claim:
    return Claim(
        claim_id=cid,
        subject="ACCT-0001",
        predicate=ClaimPredicate.SUBJECT_SHOWS_MULE_PATTERN,
        value=value,
        confidence="HIGH",
        evidence_for=list(items),
    )


def test_opposing_claims_are_reported_as_a_conflict_with_both_sides() -> None:
    report = compare([_pack("O1", _claim("C1", True)), _pack("O2", _claim("C2", False))])
    group = report.groups[0]
    assert group.verdict is Verdict.CONFLICT
    assert [c.claim_id for c in group.asserted] == ["C1"]
    assert [c.claim_id for c in group.denied] == ["C2"]
    assert summarise(report)["conflict"] == 1


def test_a_lone_claim_is_single_not_agreement() -> None:
    report = compare([_pack("O1", _claim("C1", True))])
    assert report.groups[0].verdict is Verdict.SINGLE
    assert not report.conflicts


def test_two_matching_claims_agree() -> None:
    report = compare([_pack("O1", _claim("C1", True)), _pack("O2", _claim("C2", True))])
    assert report.groups[0].verdict is Verdict.AGREE


def test_a_failed_pack_contributes_no_claims() -> None:
    failed = _pack("O2", _claim("C2", False)).model_copy(
        update={"status": "FAILED", "stop_reason": StopReason.TOOL_FAILURE}
    )
    report = compare([_pack("O1", _claim("C1", True)), failed])
    assert report.groups[0].verdict is Verdict.SINGLE
    assert not report.conflicts


def test_independent_sources_count_only_trusted_items() -> None:
    trusted = EvidenceItem(
        item_id="EV-T", source_tool="query_transactions", source_system="transactions_db",
        raw_hash="a" * 64, record_refs=["txn:T1"], trust=Trust.TRUSTED,
    )
    untrusted = EvidenceItem(
        item_id="EV-U", source_tool="read_case_notes", source_system="notes_store",
        raw_hash="b" * 64, record_refs=["note:N1.body"], trust=Trust.UNTRUSTED,
    )
    pack = _pack("O1", _claim("C1", True, items=("EV-T", "EV-U")), items=(trusted, untrusted))
    assert compare([pack]).groups[0].independent_trusted_sources == 1


# --------------------------------------------------------------------------
# Escalation
# --------------------------------------------------------------------------


def _entry(index: int, event: EventType, payload: dict) -> AuditEntry:
    draft = {
        "index": index,
        "entry_id": f"LOG-{index:06d}",
        "timestamp": "2026-03-01T00:00:00+00:00",
        "event_type": event.value,
        "actor": "gateway",
        "payload": payload,
        "policy_hash": "p" * 64,
        "prev_hash": "0" * 64,
    }
    return AuditEntry(**draft, entry_hash=hash_obj(draft))


def test_one_malformed_result_is_not_yet_repeated() -> None:
    entries = [_entry(0, EventType.DENIAL, {"reason": "MALFORMED_OUTPUT"})]
    assert not derive_triggers(entries)


def test_two_malformed_results_trigger_escalation() -> None:
    entries = [
        _entry(i, EventType.DENIAL, {"reason": "MALFORMED_OUTPUT"}) for i in range(2)
    ]
    triggers = [n.trigger for n in derive_triggers(entries)]
    assert EscalationTrigger.MALFORMED_OUTPUT_REPEATED in triggers


def test_policy_tampering_triggers_escalation() -> None:
    entries = [_entry(0, EventType.DENIAL, {"reason": "POLICY_TAMPERED", "detail": "x"})]
    assert derive_triggers(entries)[0].trigger is EscalationTrigger.POLICY_TAMPERED


def test_an_unexpected_error_alert_triggers_escalation() -> None:
    entries = [_entry(0, EventType.ALERT, {"alert": "UNEXPECTED_ERROR", "error": "boom"})]
    assert derive_triggers(entries)[0].trigger is EscalationTrigger.UNEXPECTED_ERROR


def test_escalation_is_a_one_way_door(stack) -> None:
    tracker = EscalationTracker(stack.policy, stack.audit, "CASE-001")
    assert not tracker.escalated
    tracker.note(EscalationTrigger.UNRESOLVED_CONFLICT, "they disagree")
    assert tracker.escalated
    tracker.scan()
    assert tracker.escalated  # nothing can clear it
    assert "UNRESOLVED_CONFLICT" in tracker.refuse_reason()


def test_a_trigger_disabled_in_policy_is_ignored(stack) -> None:
    narrowed = stack.policy.model_copy(
        update={"escalation": stack.policy.escalation.model_copy(update={"triggers": []})}
    )
    tracker = EscalationTracker(narrowed, stack.audit, "CASE-001")
    tracker.note(EscalationTrigger.UNRESOLVED_CONFLICT, "they disagree")
    assert not tracker.escalated
