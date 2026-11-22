"""Property tests (Phase 6): the invariants, under random adversarial pressure.

The scenario tests check the attacks we thought of. These check that the
invariants survive sequences we did not: whatever a hostile caller throws at
the gateway,

* no write ever reaches the bank through a worker,
* no budget is exceeded,
* the audit chain still verifies.

Hypothesis generates the call sequences; the invariants are asserted at the end
of each one.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from core.models import Tier  # noqa: E402

TOOL_NAMES = [
    "query_transactions",
    "read_case_notes",
    "set_account_status",
    "grant_write_access",
    "__import__",
    "",
]

ACCOUNTS = ["ACCT-0001", "ACCT-0999", "acct-0001", "ACCT-0010", "NOPE", "ACCT-99999", ""]

CALLERS = ["transaction_analyst", "notes_reviewer", "executor", "supervisor", "root", ""]

calls = st.lists(
    st.fixed_dictionaries(
        {
            "tool": st.sampled_from(TOOL_NAMES),
            "account_id": st.sampled_from(ACCOUNTS),
            "days": st.integers(min_value=-50, max_value=500),
            "limit": st.integers(min_value=-5, max_value=200),
            "caller": st.sampled_from(CALLERS),
            "extra": st.booleans(),
        }
    ),
    min_size=1,
    max_size=25,
)


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(sequence=calls)
def test_adversarial_calls_never_write_never_overspend_and_always_verify(
    stack, sequence
) -> None:
    order = stack.order("transaction_analyst")
    before = stack.tools.get_account_status("ACCT-0001")

    for step in sequence:
        args = {"account_id": step["account_id"]}
        if step["tool"] == "read_case_notes":
            args["limit"] = step["limit"]
        elif step["tool"] == "set_account_status":
            args.update({"action": "FREEZE", "idempotency_key": "0" * 64})
        else:
            args["days"] = step["days"]
        if step["extra"]:
            args["budget_override"] = 999

        # A worker's order, presented by whoever the sequence says is calling.
        stack.gateway.call(
            caller=step["caller"],
            tool=step["tool"],
            args=args,
            case_id="CASE-001",
            order=order,
        )

    # 1. No worker-side call ever changed the bank.
    assert stack.tools.get_account_status("ACCT-0001") == before

    # 2. Nobody exceeded their ceiling.
    for scope in stack.meter.scopes():
        budget = stack.meter.budget_of(scope)
        usage = stack.meter.usage(scope)
        assert usage.calls <= budget.calls, f"{scope} exceeded its call budget"
        assert usage.tokens <= budget.tokens, f"{scope} exceeded its token budget"
    global_budget = stack.policy.global_budget
    assert stack.meter.usage("__global__").calls <= global_budget.calls

    # 3. The log still verifies.
    assert stack.audit.verify_chain().ok


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    role=st.sampled_from(["transaction_analyst", "counterparty_analyst", "notes_reviewer"]),
    tool=st.sampled_from(TOOL_NAMES),
)
def test_policy_never_grants_a_write_tool_to_a_role(policy, role, tool) -> None:
    """The policy object is read-only here, so reuse across inputs is safe."""
    if policy.may_call(tool, role):
        assert policy.tools[tool].tier is Tier.READ
