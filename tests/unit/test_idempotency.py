"""At most one execution per approved action."""

from __future__ import annotations

from core.canonical import canonicalize_account, sha256_hex
from core.idempotency import IdempotencyStore
from core.models import IdempotencyState, StopReason
from tools.bank import BankTools
from tools.failure_injection import DroppedResponse, Fault, FailureInjector

PAYLOAD = sha256_hex("freeze-acct-0001")


def _store(db_path, policy):
    return IdempotencyStore(
        db_path, policy_hash=policy.policy_hash,
        canonicalize=policy.idempotency.canonicalize_target,
    )


def _attempt(store, tools, spelling, payload=PAYLOAD, write=None):
    return store.execute(
        case_id="CASE-001",
        action="FREEZE",
        target=spelling,
        payload_hash=payload,
        desired_state="FROZEN",
        write=write or (lambda key: tools.set_account_status(
            store.canonical_target(spelling), "FREEZE", key)),
        read_back=lambda: tools.get_account_status("ACCT-0001"),
    )


def test_unicode_lookalikes_collapse_to_one_key(db_path, policy) -> None:
    store = _store(db_path, policy)
    assert canonicalize_account("acct-0001") == "ACCT-0001"
    assert canonicalize_account("ACCT‑0001") == "ACCT-0001"  # non-breaking hyphen
    assert canonicalize_account("  ACCT—0001  ") == "ACCT-0001"  # em dash
    assert canonicalize_account("ＡＣＣＴ－０００１") == "ACCT-0001"  # fullwidth
    keys = {
        store.key_for("CASE-001", "FREEZE", s)
        for s in ("acct-0001", "ACCT-0001", "ACCT‑0001", " ACCT-0001 ")
    }
    assert len(keys) == 1
    store.close()


def test_the_second_attempt_is_a_duplicate_not_a_second_write(db_path, policy) -> None:
    store = _store(db_path, policy)
    tools = BankTools(db_path)

    first = _attempt(store, tools, "acct-0001")
    second = _attempt(store, tools, "ACCT‑0001")

    assert first.ok and first.wrote and first.state is IdempotencyState.CONFIRMED
    assert not second.ok and not second.wrote
    assert second.stop_reason is StopReason.DUPLICATE_ACTION
    assert first.key == second.key
    assert tools.get_account_status("ACCT-0001") == "FROZEN"
    store.close()
    tools.close()


def test_same_key_different_payload_is_a_conflict(db_path, policy) -> None:
    store = _store(db_path, policy)
    tools = BankTools(db_path)
    _attempt(store, tools, "ACCT-0001", payload=PAYLOAD)
    clash = _attempt(store, tools, "ACCT-0001", payload=sha256_hex("something-else"))
    assert not clash.ok
    assert clash.stop_reason is StopReason.IDEMPOTENCY_CONFLICT
    store.close()
    tools.close()


def test_a_lost_response_is_resolved_by_reading_back(db_path, policy) -> None:
    """The write landed. The reply did not. No second write may be issued."""
    store = _store(db_path, policy)
    injector = FailureInjector().arm("set_account_status", Fault(drop_response=True))
    tools = BankTools(db_path, injector)
    writes = {"n": 0}

    def write(key):
        writes["n"] += 1
        try:
            return tools.set_account_status("ACCT-0001", "FREEZE", key)
        except DroppedResponse:
            return "UNKNOWN"

    result = store.execute(
        case_id="CASE-001", action="FREEZE", target="ACCT-0001", payload_hash=PAYLOAD,
        desired_state="FROZEN", write=write,
        read_back=lambda: tools.get_account_status("ACCT-0001"),
        write_response_unknown=lambda r: r == "UNKNOWN",
    )
    assert result.ok
    assert result.state is IdempotencyState.CONFIRMED
    assert writes["n"] == 1
    assert "read-back confirmed" in result.detail
    store.close()
    tools.close()


def test_an_account_already_in_the_target_state_is_not_written_again(db_path, policy) -> None:
    store = _store(db_path, policy)
    tools = BankTools(db_path)
    tools.set_account_status("ACCT-0001", "FREEZE", "0" * 64)
    result = _attempt(store, tools, "ACCT-0001")
    assert result.ok
    assert not result.wrote
    assert result.state is IdempotencyState.CONFIRMED
    store.close()
    tools.close()


def test_state_progresses_intent_executed_confirmed(db_path, policy) -> None:
    from core.audit_log import AuditLog

    audit = AuditLog(db_path, "logs/_test_idem.jsonl")
    store = IdempotencyStore(
        db_path, audit=audit, policy_hash=policy.policy_hash,
        canonicalize=policy.idempotency.canonicalize_target,
    )
    tools = BankTools(db_path)
    _attempt(store, tools, "ACCT-0001")
    states = [
        e.payload["state"]
        for e in audit.entries()
        if e.event_type.value == "ACTION" and "state" in e.payload
    ]
    assert states[:3] == ["INTENT", "EXECUTED", "CONFIRMED"]
    store.close()
    tools.close()
    audit.close()


def test_a_failed_write_leaves_the_claim_at_intent(db_path, policy) -> None:
    store = _store(db_path, policy)
    tools = BankTools(db_path)
    result = _attempt(store, tools, "ACCT-0001", write=lambda key: None)
    assert not result.ok
    assert result.state is IdempotencyState.INTENT
    assert result.stop_reason is StopReason.TOOL_FAILURE
    assert tools.get_account_status("ACCT-0001") == "ACTIVE"
    store.close()
    tools.close()
