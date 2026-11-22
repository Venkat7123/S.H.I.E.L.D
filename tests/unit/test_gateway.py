"""The gateway's thirteen checks."""

from __future__ import annotations

from core.models import Budget, DenialReason, StopReason, Trust
from tools.failure_injection import Fault


def test_read_tool_in_the_order_succeeds(stack) -> None:
    order = stack.order("transaction_analyst")
    result = stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)
    assert result.ok
    assert result.records
    assert stack.raw.has(result.raw_hash)


def test_worker_cannot_call_a_write_tool(stack) -> None:
    order = stack.order("transaction_analyst")
    denial = stack.client(order).call(
        "set_account_status", account_id="ACCT-0001", action="FREEZE", idempotency_key="k"
    )
    assert not denial.ok
    assert denial.reason is DenialReason.WRITE_TOOL_DENIED


def test_unlisted_tool_is_denied_by_default(stack) -> None:
    order = stack.order("transaction_analyst")
    denial = stack.client(order).call("grant_write_access", account_id="ACCT-0001")
    assert denial.reason is DenialReason.UNKNOWN_TOOL


def test_tool_outside_the_order_is_denied(stack) -> None:
    order = stack.order("transaction_analyst")
    denial = stack.client(order).call("read_case_notes", account_id="ACCT-0001", limit=5)
    assert not denial.ok
    assert denial.reason in (DenialReason.TOOL_NOT_ALLOWED, DenialReason.TOOL_FORBIDDEN)


def test_edited_order_fails_its_hash(stack) -> None:
    order = stack.order("transaction_analyst")
    widened = order.model_copy(
        update={"allowed_tools": ["query_transactions", "set_account_status"]}
    )
    denial = stack.gateway.call(
        caller="transaction_analyst",
        tool="set_account_status",
        args={"account_id": "ACCT-0001", "action": "FREEZE", "idempotency_key": "0" * 64},
        case_id="CASE-001",
        order=widened,
    )
    assert denial.reason is DenialReason.ORDER_HASH_INVALID


def test_raised_budget_in_an_edited_order_fails_its_hash(stack) -> None:
    order = stack.order("transaction_analyst")
    greedy = order.model_copy(update={"budget": Budget(calls=999, tokens=999999, seconds=9999)})
    denial = stack.gateway.call(
        caller="transaction_analyst",
        tool="query_transactions",
        args={"account_id": "ACCT-0001", "days": 30},
        case_id="CASE-001",
        order=greedy,
    )
    assert denial.reason is DenialReason.ORDER_HASH_INVALID


def test_caller_cannot_use_another_role_s_order(stack) -> None:
    order = stack.order("transaction_analyst")
    denial = stack.gateway.call(
        caller="notes_reviewer",
        tool="query_transactions",
        args={"account_id": "ACCT-0001", "days": 30},
        case_id="CASE-001",
        order=order,
    )
    assert denial.reason is DenialReason.CALLER_MISMATCH


def test_arguments_are_validated_against_policy(stack) -> None:
    order = stack.order("transaction_analyst")
    client = stack.client(order)
    assert client.call("query_transactions", account_id="NOPE", days=5).reason is (
        DenialReason.ARGS_INVALID
    )
    assert client.call("query_transactions", account_id="ACCT-0001", days=900).reason is (
        DenialReason.ARGS_INVALID
    )
    assert client.call(
        "query_transactions", account_id="ACCT-0001", days=5, budget_override=999
    ).reason is DenialReason.ARGS_INVALID


def test_worker_cannot_pivot_to_an_account_it_only_saw_in_untrusted_text(stack) -> None:
    order = stack.order("transaction_analyst")
    client = stack.client(order)
    client.call("query_transactions", account_id="ACCT-0001", days=30)
    denial = client.call("query_transactions", account_id="ACCT-0999", days=30)
    assert denial.reason is DenialReason.TARGET_NOT_PERMITTED


def test_worker_may_pivot_to_a_trusted_counterparty(stack) -> None:
    order = stack.order("transaction_analyst")
    client = stack.client(order)
    client.call("query_transactions", account_id="ACCT-0001", days=30)
    result = client.call("query_transactions", account_id="ACCT-0010", days=30)
    assert result.ok


def test_budget_is_enforced_and_retries_cost(stack) -> None:
    order = stack.order("transaction_analyst", budget=Budget(calls=2, tokens=5000, seconds=60))
    stack.meter.register("transaction_analyst", order.budget)
    client = stack.client(order)
    assert client.call("query_transactions", account_id="ACCT-0001", days=30).ok
    assert client.call("query_transactions", account_id="ACCT-0001", days=30).ok
    third = client.call("query_transactions", account_id="ACCT-0001", days=30)
    assert third.stop_reason is StopReason.BUDGET_EXHAUSTED


def test_an_unregistered_caller_has_no_budget_rather_than_an_unlimited_one(stack) -> None:
    order = stack.order("notes_reviewer", tools=["read_case_notes"])
    stack.meter._accounts.pop("notes_reviewer", None)
    denial = stack.client(order).call("read_case_notes", account_id="ACCT-0001", limit=5)
    assert denial.reason is DenialReason.BUDGET_EXHAUSTED


def test_transient_failure_is_retried_then_succeeds(stack) -> None:
    stack.injector.arm("query_transactions", Fault(raise_error=True, message="blip"), times=2)
    order = stack.order("transaction_analyst")
    result = stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)
    assert result.ok


def test_malformed_output_is_discarded_not_repaired(stack) -> None:
    stack.injector.arm("read_case_notes", Fault(malformed=True), times=3)
    order = stack.order("notes_reviewer", tools=["read_case_notes"])
    denial = stack.client(order).call("read_case_notes", account_id="ACCT-0001", limit=5)
    assert denial.reason is DenialReason.MALFORMED_OUTPUT
    assert denial.stop_reason is StopReason.MALFORMED_OUTPUT


def test_policy_tamper_denies_every_call(stack) -> None:
    """Editing the policy file mid-run is caught before the next call runs."""
    order = stack.order("transaction_analyst")
    client = stack.client(order)
    assert client.call("query_transactions", account_id="ACCT-0001", days=30).ok

    text = stack.policy_file.read_text(encoding="utf-8")
    stack.policy_file.write_text(
        text.replace("calls: 10", "calls: 999"), encoding="utf-8"
    )

    denial = client.call("query_transactions", account_id="ACCT-0001", days=30)
    assert denial.reason is DenialReason.POLICY_TAMPERED
    assert denial.stop_reason is StopReason.POLICY_TAMPERED
    assert stack.gateway.policy_tampered


def test_a_missing_policy_file_fails_closed(stack) -> None:
    order = stack.order("transaction_analyst")
    stack.policy_file.unlink()
    denial = stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)
    assert denial.reason is DenialReason.POLICY_TAMPERED


def test_every_call_is_logged_before_it_runs(stack) -> None:
    order = stack.order("transaction_analyst")
    stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)
    types = [e.event_type.value for e in stack.audit.entries()]
    assert types.index("TOOL_CALL") < types.index("TOOL_RESULT")


def test_denials_are_logged(stack) -> None:
    order = stack.order("transaction_analyst")
    stack.client(order).call("set_account_status", account_id="ACCT-0001", action="FREEZE",
                             idempotency_key="0" * 64)
    denials = [e for e in stack.audit.entries() if e.event_type.value == "DENIAL"]
    assert denials
    assert denials[-1].payload["reason"] == "WRITE_TOOL_DENIED"


def test_untrusted_fields_are_named_in_the_result_log(stack) -> None:
    order = stack.order("transaction_analyst")
    stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)
    results = [e for e in stack.audit.entries() if e.event_type.value == "TOOL_RESULT"]
    assert results[-1].payload["untrusted_fields"] == ["description"]


def test_raw_output_is_stored_and_addressed_by_its_hash(stack) -> None:
    order = stack.order("transaction_analyst")
    result = stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)
    payload = stack.raw.get(result.raw_hash)
    assert isinstance(payload, list)
    assert stack.raw.tool_of(result.raw_hash) == "query_transactions"
    assert stack.raw.ref_exists(result.raw_hash, "txn:TXN-0002.to_account")
    assert not stack.raw.ref_exists(result.raw_hash, "txn:TXN-9999.to_account")


def test_write_tool_is_never_retried_by_the_gateway(stack) -> None:
    """A lost write response must reach the caller as "unknown", not a retry."""
    stack.injector.arm("set_account_status", Fault(drop_response=True), times=1)
    client = stack.gateway.executor_client("CASE-001")
    outcome = client.call(
        "set_account_status",
        account_id="ACCT-0001",
        action="FREEZE",
        idempotency_key="a" * 64,
    )
    assert not outcome.ok
    assert outcome.response_unknown
    # The write did land - which is exactly why retrying blindly is wrong.
    assert stack.tools.get_account_status("ACCT-0001") == "FROZEN"
