"""Trust at origin, and the fact that it is a one-way door."""

from __future__ import annotations

import pytest

from core.models import LabeledValue, Trust
from core.provenance import TrustUpgradeError


def _read(stack):
    order = stack.order("transaction_analyst")
    return stack.client(order).call("query_transactions", account_id="ACCT-0001", days=30)


def test_policy_decides_trust_not_the_caller(stack) -> None:
    result = _read(stack)
    record = next(r for r in result.records if r.record_id == "txn:TXN-0002")
    assert record.fields["to_account"].trust is Trust.TRUSTED
    assert record.fields["amount"].trust is Trust.TRUSTED
    # description is free text written by whoever sent the money
    assert record.fields["description"].trust is Trust.UNTRUSTED


def test_untrusted_can_never_be_upgraded_to_trusted(stack) -> None:
    """The guarantee, tested directly: try to relabel and be refused."""
    _read(stack)
    source_record = "txn:TXN-0002.description"
    assert stack.ledger.trust_of(source_record) is Trust.UNTRUSTED

    # Pretend policy now says description is trusted, and relabel the same
    # record. First entry must win.
    tool_policy = stack.policy.tool("query_transactions")
    object.__setattr__(
        tool_policy.field_trust, "__pydantic_extra__", {"description": "trusted"}
    )
    with pytest.raises(TrustUpgradeError):
        stack.ledger.label(
            value="anything",
            source_tool="query_transactions",
            record_id="TXN-0002",
            record_kind="txn",
            field_name="description",
            raw_hash="0" * 64,
            case_id="CASE-001",
        )
    assert stack.ledger.trust_of(source_record) is Trust.UNTRUSTED


def test_a_forged_trusted_label_does_not_verify(stack) -> None:
    """An agent can build any object it likes; the ledger is the arbiter."""
    _read(stack)
    forged = LabeledValue(
        value="ACCT-0999",
        source_tool="query_transactions",
        source_record="txn:TXN-0002.description",
        trust=Trust.TRUSTED,  # a lie
        raw_hash=stack.ledger._fetch("txn:TXN-0002.description")["raw_hash"],
    )
    result = stack.ledger.verify(forged)
    assert not result.ok
    assert "untrusted at origin" in result.reason


def test_a_label_pointing_at_a_record_that_does_not_exist_fails(stack) -> None:
    _read(stack)
    invented = LabeledValue(
        value="ACCT-0999",
        source_tool="query_transactions",
        source_record="txn:TXN-9999.to_account",
        trust=Trust.TRUSTED,
        raw_hash="0" * 64,
    )
    assert not stack.ledger.verify(invented).ok


def test_a_label_claiming_the_wrong_value_fails(stack) -> None:
    """Right record, right trust level, wrong value."""
    _read(stack)
    row = stack.ledger._fetch("txn:TXN-0002.to_account")
    tampered = LabeledValue(
        value="ACCT-0999",  # the record actually holds ACCT-0001
        source_tool="query_transactions",
        source_record="txn:TXN-0002.to_account",
        trust=Trust.TRUSTED,
        raw_hash=row["raw_hash"],
    )
    result = stack.ledger.verify(tampered)
    assert not result.ok
    assert "value mismatch" in result.reason


def test_an_honest_label_verifies(stack) -> None:
    _read(stack)
    row = stack.ledger._fetch("txn:TXN-0002.to_account")
    honest = LabeledValue(
        value="ACCT-0001",
        source_tool="query_transactions",
        source_record="txn:TXN-0002.to_account",
        trust=Trust.TRUSTED,
        raw_hash=row["raw_hash"],
    )
    assert stack.ledger.verify(honest).ok


def test_trusted_account_set_excludes_ids_mentioned_in_untrusted_text(stack) -> None:
    """ACCT-0999 is named inside a description. It must not become a target."""
    _read(stack)
    trusted = stack.ledger.trusted_account_values("CASE-001")
    assert "ACCT-0001" in trusted
    assert "ACCT-0010" in trusted
    assert "ACCT-0999" not in trusted
