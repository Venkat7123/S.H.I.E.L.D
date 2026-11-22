"""Running one case end to end.

The order of operations here *is* part of the security design, so it is worth
reading as a sequence rather than as plumbing:

1. the plan is made and **locked** before any worker touches untrusted data;
2. workers run inside their orders and return structured packs;
3. claims are compared **in code**;
4. a conflict escalates, and an escalated case never reaches the executor;
5. only then does the supervisor propose, and the executor re-derives
   everything before asking a human.

Any unexpected exception at any point escalates the case rather than being
swallowed or retried. A run that goes wrong in a way nobody anticipated ends
in front of a person, not in a write.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from core.approval import ApprovalGate, Decider, auto_reject
from core.audit_log import AuditLog
from core.budget import BudgetMeter
from core.compare import compare, summarise
from core.escalation import EscalationTracker
from core.executor import Executor
from core.gateway import Gateway
from core.idempotency import IdempotencyStore
from core.models import (
    ActionOutcome,
    CaseReport,
    CaseStatus,
    EscalationTrigger,
    EventType,
    EvidencePack,
    StopReason,
    WorkerSummary,
    utcnow,
)
from core.provenance import ProvenanceLedger
from core.raw_store import RawStore
from agents.llm import build_llm
from agents.stubs import Behaviour, build_script, default_behaviour
from agents.supervisor import PlanLockedError, Supervisor
from agents.worker import Worker
from policy.loader import load_policy
from tools.bank import BankTools
from tools.failure_injection import FailureInjector

DEFAULT_CONFIG = "config.yaml"


def _no_sleep(_seconds: float) -> None:
    """Retry backoff, skipped. Used by scripted runs only."""


def load_config(path: str | Path = DEFAULT_CONFIG) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"llm": {"mode": "stub"}, "run": {}}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


class RunOptions(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    db_path: str = "data/shield.db"
    policy_path: str = "policy/policy.yaml"
    jsonl_path: str = "logs/audit.jsonl"
    config_path: str = DEFAULT_CONFIG
    scenario_id: str | None = None
    behaviour: Behaviour | None = None
    injector: FailureInjector | None = None
    decider: Any = None
    enable_optional_checks: bool = False
    fast: bool = True  # skip real retry backoff sleeps


class CaseRunner:
    """Owns the wiring for one case run and tears it down afterwards."""

    def __init__(self, options: RunOptions | None = None) -> None:
        self.opt = options or RunOptions()
        self.config = load_config(self.opt.config_path)
        self.policy = load_policy(self.opt.policy_path)

        self.audit = AuditLog(self.opt.db_path, self.opt.jsonl_path)
        self.meter = BudgetMeter(self.policy.global_budget)
        self.raw = RawStore(self.opt.db_path)
        self.ledger = ProvenanceLedger(self.policy, self.raw, self.opt.db_path)
        self.injector = self.opt.injector or FailureInjector()

        run_cfg = self.config.get("run", {})
        self.tools = BankTools(
            self.opt.db_path,
            self.injector,
            timeout_seconds=float(run_cfg.get("tool_timeout_seconds", 5)),
        )
        self.gateway = Gateway(
            policy=self.policy,
            audit=self.audit,
            budget=self.meter,
            raw_store=self.raw,
            ledger=self.ledger,
            tools=self.tools,
            policy_path=self.opt.policy_path,
            tool_timeout_seconds=float(run_cfg.get("tool_timeout_seconds", 5)),
            max_retries=int(run_cfg.get("tool_max_retries", 3)),
            backoff_seconds=tuple(run_cfg.get("retry_backoff_seconds", [1, 2, 4])),
            # The demo must stay under a minute, so scripted runs skip the real
            # backoff waits. The retries themselves - and the budget they cost -
            # are unchanged.
            sleep=_no_sleep if self.opt.fast else time.sleep,
        )
        self.idempotency = IdempotencyStore(
            self.opt.db_path,
            audit=self.audit,
            policy_hash=self.policy.policy_hash,
            canonicalize=self.policy.idempotency.canonicalize_target,
        )
        self.approvals = ApprovalGate(
            self.opt.db_path, audit=self.audit, policy_hash=self.policy.policy_hash
        )
        self.executor = Executor(
            policy=self.policy,
            audit=self.audit,
            gateway=self.gateway,
            ledger=self.ledger,
            raw_store=self.raw,
            idempotency=self.idempotency,
            approvals=self.approvals,
            tools=self.tools,
            enable_independent_sources=self.opt.enable_optional_checks,
        )
        self.max_iterations = int(run_cfg.get("max_worker_iterations", 20))
        # Populated by the optional Phase 6 check, when enabled.
        self.missed_action = None

    # ------------------------------------------------------------------

    def run(self, case_id: str, decider: Decider | None = None) -> CaseReport:
        started = utcnow()
        escalation = EscalationTracker(self.policy, self.audit, case_id)
        decider = decider or self.opt.decider or auto_reject

        case = self.tools.get_case(case_id)
        if case is None:
            raise ValueError(f"unknown case {case_id!r}")

        behaviour = self.opt.behaviour or default_behaviour(
            case_id, case["subject_account"]
        )
        llm = build_llm(self.config, build_script(behaviour))
        supervisor = Supervisor(
            policy=self.policy,
            audit=self.audit,
            llm=llm,
            ledger=self.ledger,
            gateway=self.gateway,
        )
        self.meter.register("supervisor", self.policy.global_budget)

        packs: list[EvidencePack] = []
        summaries: list[WorkerSummary] = []
        proposal = None
        action: ActionOutcome | None = None

        try:
            # 1-2. plan, then lock, then work.
            orders = supervisor.plan(case)
            for order in orders:
                role_policy = self.policy.role(order.worker_role)
                if role_policy:
                    self.meter.register(order.worker_role, role_policy.budget)

            roles = {o.order_id: o.worker_role for o in orders}
            for order in orders:
                worker = Worker(
                    order,
                    self.gateway.client_for(order),
                    llm,
                    max_iterations=self.max_iterations,
                )
                pack = worker.run()
                packs.append(pack)
                summaries.append(
                    WorkerSummary(
                        order_id=order.order_id,
                        worker_role=order.worker_role,
                        status=pack.status,
                        stop_reason=pack.stop_reason,
                        missing=list(pack.missing),
                        usage=self.meter.usage(order.worker_role),
                    )
                )

            # 3. compare in code.
            comparison = compare(packs, roles)
            self.audit.append(
                EventType.DECISION,
                "comparator",
                {"case_id": case_id, "comparison": summarise(comparison)},
                self.policy.policy_hash,
            )

            # 4. escalate on disagreement, and on anything the log reveals.
            for group in comparison.conflicts:
                escalation.note(
                    EscalationTrigger.UNRESOLVED_CONFLICT,
                    f"workers disagree on {group.subject} / {group.predicate.value}",
                )
            escalation.scan()

            # A compromised supervisor trying to widen authority after reading
            # the packs. Denied, logged, and the run continues.
            if behaviour.issue_extra_order:
                try:
                    supervisor.issue_additional_order(case_id, "transaction_analyst")
                except PlanLockedError:
                    pass

            # 5. propose, then check everything again from storage.
            proposal = supervisor.propose(case, packs, comparison)
            action = self.executor.execute(
                case_id=case_id,
                proposal=proposal,
                packs=packs,
                comparison=comparison,
                escalation=escalation,
                decider=decider,
                ai_summary=supervisor.summary,
            )

            # 6. Optional: did the supervisor fail to propose a needed action?
            if self.opt.enable_optional_checks:
                from core.missed_action import check_for_missed_action

                self.missed_action = check_for_missed_action(
                    case_id=case_id,
                    proposal=proposal,
                    packs=packs,
                    executor=self.executor,
                    policy=self.policy,
                    audit=self.audit,
                    subject_account=case["subject_account"],
                )

        except Exception as exc:
            # Fail safe. An unanticipated error is a reason to stop and ask a
            # human, never a reason to carry on.
            escalation.note(
                EscalationTrigger.UNEXPECTED_ERROR, f"{type(exc).__name__}: {exc}"
            )
            comparison = compare(packs, {})

        status = self._status(packs, escalation, action)
        missing = sorted({m for p in packs for m in p.missing})

        self.audit.append(
            EventType.STOP,
            "runner",
            {
                "case_id": case_id,
                "scenario": self.opt.scenario_id,
                "status": status.value,
                "stop_reasons": sorted({p.stop_reason.value for p in packs}),
                "missing": missing,
                "escalations": [n.trigger.value for n in escalation.notices()],
                "action": action.model_dump(mode="json") if action else None,
            },
            self.policy.policy_hash,
        )

        return CaseReport(
            case_id=case_id,
            scenario_id=self.opt.scenario_id,
            status=status,
            policy_hash=self.policy.policy_hash,
            workers=summaries,
            packs=packs,
            comparison=comparison,
            proposal=proposal,
            action=action,
            escalations=escalation.notices(),
            missing=missing,
            ai_summary=supervisor.summary,
            started_at=started,
            finished_at=utcnow(),
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _status(
        packs: list[EvidencePack],
        escalation: EscalationTracker,
        action: ActionOutcome | None,
    ) -> CaseStatus:
        if escalation.escalated:
            return CaseStatus.ESCALATED
        if not packs or all(p.status == "FAILED" for p in packs):
            return CaseStatus.FAILED
        if any(p.status != "COMPLETE" for p in packs):
            return CaseStatus.PARTIAL
        if action and not action.executed and action.stop_reason not in (
            StopReason.COMPLETED,
        ):
            # The investigation finished cleanly; the action was refused. That
            # is a complete case with a refusal, not a failed one.
            return CaseStatus.COMPLETE
        return CaseStatus.COMPLETE

    def close(self) -> None:
        for component in (
            self.approvals,
            self.idempotency,
            self.ledger,
            self.raw,
            self.tools,
            self.audit,
        ):
            try:
                component.close()
            except Exception:
                pass
