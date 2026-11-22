"""Shared fixtures.

Every test gets its own temporary database and its own copy of the policy
file, so tests cannot leak state into one another and the policy-tamper test
can edit a file without breaking the rest of the suite.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.approval import ApprovalGate  # noqa: E402
from core.audit_log import AuditLog  # noqa: E402
from core.budget import BudgetMeter  # noqa: E402
from core.executor import Executor  # noqa: E402
from core.gateway import Gateway  # noqa: E402
from core.idempotency import IdempotencyStore  # noqa: E402
from core.models import Budget, WorkOrder  # noqa: E402
from core.provenance import ProvenanceLedger  # noqa: E402
from core.raw_store import RawStore  # noqa: E402
from data.seed import seed  # noqa: E402
from policy.loader import Policy, load_policy  # noqa: E402
from tools.bank import BankTools  # noqa: E402
from tools.failure_injection import FailureInjector  # noqa: E402


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    dest = tmp_path / "policy.yaml"
    shutil.copyfile(ROOT / "policy" / "policy.yaml", dest)
    return dest


@pytest.fixture
def policy(policy_file: Path) -> Policy:
    return load_policy(policy_file)


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = tmp_path / "shield.db"
    seed(path)
    return str(path)


@dataclass
class Stack:
    policy: Policy
    policy_file: Path
    db_path: str
    audit: AuditLog
    meter: BudgetMeter
    raw: RawStore
    ledger: ProvenanceLedger
    tools: BankTools
    gateway: Gateway
    idempotency: IdempotencyStore
    approvals: ApprovalGate
    executor: Executor
    injector: FailureInjector

    def order(
        self,
        role: str = "transaction_analyst",
        *,
        case_id: str = "CASE-001",
        target: str = "ACCT-0001",
        tools: list[str] | None = None,
        budget: Budget | None = None,
    ) -> WorkOrder:
        role_policy = self.policy.role(role)
        order = WorkOrder.new(
            order_id=f"ORD-{case_id}-{role}",
            case_id=case_id,
            worker_role=role,
            goal="investigate",
            success_criteria=["evidence gathered"],
            allowed_tools=tools if tools is not None else list(role_policy.tools),
            forbidden_actions=self.policy.write_tools(),
            budget=budget or role_policy.budget,
            required_evidence=["transactions"],
            stop_conditions=["budget exhausted"],
            target_account=target,
            policy_hash=self.policy.policy_hash,
        )
        if not self.meter.known(role):
            self.meter.register(role, order.budget)
        return order

    def client(self, order: WorkOrder):
        return self.gateway.client_for(order)


@pytest.fixture
def stack(policy: Policy, policy_file: Path, db_path: str, tmp_path: Path) -> Stack:
    audit = AuditLog(db_path, tmp_path / "audit.jsonl")
    meter = BudgetMeter(policy.global_budget)
    raw = RawStore(db_path)
    ledger = ProvenanceLedger(policy, raw, db_path)
    injector = FailureInjector()
    tools = BankTools(db_path, injector)
    gateway = Gateway(
        policy=policy,
        audit=audit,
        budget=meter,
        raw_store=raw,
        ledger=ledger,
        tools=tools,
        policy_path=policy_file,
        sleep=lambda _s: None,
    )
    idempotency = IdempotencyStore(
        db_path,
        audit=audit,
        policy_hash=policy.policy_hash,
        canonicalize=policy.idempotency.canonicalize_target,
    )
    approvals = ApprovalGate(db_path, audit=audit, policy_hash=policy.policy_hash)
    executor = Executor(
        policy=policy,
        audit=audit,
        gateway=gateway,
        ledger=ledger,
        raw_store=raw,
        idempotency=idempotency,
        approvals=approvals,
        tools=tools,
    )
    s = Stack(
        policy=policy,
        policy_file=policy_file,
        db_path=db_path,
        audit=audit,
        meter=meter,
        raw=raw,
        ledger=ledger,
        tools=tools,
        gateway=gateway,
        idempotency=idempotency,
        approvals=approvals,
        executor=executor,
        injector=injector,
    )
    yield s
    for component in (approvals, idempotency, ledger, raw, tools, audit):
        try:
            component.close()
        except Exception:
            pass
