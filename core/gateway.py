"""The policy gateway: the only way anything reaches a tool.

Thirteen checks run in a fixed order on every call, and the first failure stops
the call and logs a denial. The order is not arbitrary - cheap identity checks
come before expensive ones, budget is reserved before the call so failures
still cost, and the audit entry is written *before* execution so an action can
never happen unrecorded.

Two decisions worth stating outright:

**Writes are never retried here.** A lost response on a write is not a reason
to write again - it is a reason to read back and find out what happened. The
gateway reports ``response_unknown`` and the idempotency store decides. Retrying
a write at this layer is precisely how an account gets frozen twice.

**Enforcement lives only here.** The tools do not check permissions, and
neither do the agents. One copy of the rules, in code, outside the model.

Trusted core: no LLM, no ``agents`` imports. ``tests/unit/test_no_llm_in_core.py``
fails the build if that ever stops being true.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from core.audit_log import AuditLog, AuditWriteError
from core.budget import BudgetMeter
from core.models import (
    DenialReason,
    EventType,
    GatewayDenial,
    GatewayOutcome,
    LabeledRecord,
    StopReason,
    Tier,
    ToolResult,
    Trust,
    WorkOrder,
)
from core.provenance import ProvenanceLedger, TrustUpgradeError
from core.raw_store import RawStore
from policy.loader import Policy, compute_policy_hash
from tools.bank import BankTools, MalformedToolOutput, ToolError, ToolTimeout, validate_output
from tools.failure_injection import DroppedResponse

EXECUTOR = "executor"
DEFAULT_BACKOFF = (1.0, 2.0, 4.0)


class Gateway:
    def __init__(
        self,
        *,
        policy: Policy,
        audit: AuditLog,
        budget: BudgetMeter,
        raw_store: RawStore,
        ledger: ProvenanceLedger,
        tools: BankTools,
        policy_path: str | Path = "policy/policy.yaml",
        tool_timeout_seconds: float = 5.0,
        max_retries: int = 3,
        backoff_seconds: tuple[float, ...] = DEFAULT_BACKOFF,
        sleep=time.sleep,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.budget = budget
        self.raw = raw_store
        self.ledger = ledger
        self.tools = tools
        self.policy_path = Path(policy_path)
        self.tool_timeout_seconds = tool_timeout_seconds
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._sleep = sleep
        self.policy_tampered = False
        self._locked_cases: set[str] = set()

    # ------------------------------------------------------------------
    # Plan locking
    # ------------------------------------------------------------------

    def lock_plan(self, case_id: str) -> None:
        """No further work orders may be issued for this case.

        Called once the supervisor's plan is frozen and before any worker reads
        untrusted data. After this, a supervisor that has been hijacked by
        something it read cannot widen anyone's authority.
        """
        self._locked_cases.add(case_id)

    def plan_locked(self, case_id: str) -> bool:
        return case_id in self._locked_cases

    # ------------------------------------------------------------------
    # The call path
    # ------------------------------------------------------------------

    def call(
        self,
        *,
        caller: str,
        tool: str,
        args: dict[str, Any],
        case_id: str,
        order: WorkOrder | None = None,
    ) -> GatewayOutcome:
        call_id = f"CALL-{uuid.uuid4().hex[:12]}"
        tool_policy = self.policy.tool(tool)

        def deny(
            reason: DenialReason,
            detail: str,
            *,
            stop: StopReason = StopReason.DENIED,
            response_unknown: bool = False,
        ) -> GatewayDenial:
            try:
                entry = self.audit.append(
                    EventType.DENIAL,
                    caller,
                    {
                        "case_id": case_id,
                        "call_id": call_id,
                        "tool": tool,
                        "args": args,
                        "reason": reason.value,
                        "detail": detail,
                        "order_id": order.order_id if order else None,
                    },
                    self.policy.policy_hash,
                )
                log_id = entry.entry_id
            except AuditWriteError:
                log_id = "UNLOGGED"
            return GatewayDenial(
                call_id=call_id,
                tool=tool,
                reason=reason,
                detail=detail,
                log_entry_id=log_id,
                stop_reason=stop,
                response_unknown=response_unknown,
            )

        # -- 1. caller identity ----------------------------------------
        if caller != EXECUTOR:
            if order is None:
                return deny(DenialReason.CALLER_MISMATCH, "worker call without a work order")
            if order.worker_role != caller:
                return deny(
                    DenialReason.CALLER_MISMATCH,
                    f"caller {caller!r} does not match order role {order.worker_role!r}",
                )
            if order.case_id != case_id:
                return deny(
                    DenialReason.CALLER_MISMATCH,
                    f"order belongs to case {order.case_id!r}, not {case_id!r}",
                )

            # -- 2. order hash still valid -----------------------------
            if not order.hash_is_valid():
                return deny(
                    DenialReason.ORDER_HASH_INVALID,
                    "work order contents do not match its order_hash",
                )
            if order.policy_hash != self.policy.policy_hash:
                return deny(
                    DenialReason.ORDER_HASH_INVALID,
                    "work order was issued under a different policy",
                )

        # -- 3. tool permitted -----------------------------------------
        if tool_policy is None:
            return deny(DenialReason.UNKNOWN_TOOL, f"{tool!r} is not in the policy (default deny)")

        if tool_policy.tier is Tier.WRITE and caller != EXECUTOR:
            return deny(
                DenialReason.WRITE_TOOL_DENIED,
                f"{tool!r} is a write tool; only the executor may call it",
            )
        if not self.policy.may_call(tool, caller):
            return deny(
                DenialReason.TOOL_NOT_ALLOWED,
                f"policy does not grant {tool!r} to {caller!r}",
            )
        if order is not None:
            if tool in order.forbidden_actions:
                return deny(
                    DenialReason.TOOL_FORBIDDEN,
                    f"{tool!r} is listed in the order's forbidden_actions",
                )
            if tool not in order.allowed_tools:
                return deny(
                    DenialReason.TOOL_NOT_ALLOWED,
                    f"{tool!r} is not in the order's allowed_tools",
                )

        # -- 4. arguments ----------------------------------------------
        problem = tool_policy.validate_args(args)
        if problem:
            return deny(DenialReason.ARGS_INVALID, problem)

        # -- 5. read target ---------------------------------------------
        if caller != EXECUTOR and "account_id" in args:
            target = str(args["account_id"])
            permitted = {order.target_account} | self.ledger.trusted_account_values(case_id)
            if target not in permitted:
                return deny(
                    DenialReason.TARGET_NOT_PERMITTED,
                    f"{target} is neither the order target nor a TRUSTED "
                    "account seen earlier in this case",
                )

        # -- 6. reserve budget -------------------------------------------
        scope = caller
        if not self.budget.known(scope):
            if caller != EXECUTOR:
                # Fail closed: an unregistered worker has no allowance, not an
                # unlimited one.
                return deny(
                    DenialReason.BUDGET_EXHAUSTED,
                    f"no budget registered for {caller!r}",
                    stop=StopReason.BUDGET_EXHAUSTED,
                )
            # The executor's writes are rare, human-approved and capped by the
            # idempotency store, but they still answer to the case-wide ceiling.
            self.budget.register(scope, self.policy.global_budget)
        decision = self.budget.reserve(scope, calls=1)
        if not decision.ok:
            return deny(
                DenialReason.BUDGET_EXHAUSTED,
                decision.reason,
                stop=StopReason.BUDGET_EXHAUSTED,
            )
        reservation = decision.reservation

        # -- 7. policy unchanged on disk ---------------------------------
        if not self._policy_intact():
            self.policy_tampered = True
            self._alert("POLICY_TAMPERED", {"case_id": case_id, "call_id": call_id})
            return deny(
                DenialReason.POLICY_TAMPERED,
                "policy file hash changed since load; denying all calls",
                stop=StopReason.POLICY_TAMPERED,
            )

        # -- 8. log the intent before doing anything ----------------------
        try:
            intent = self.audit.append(
                EventType.TOOL_CALL,
                caller,
                {
                    "case_id": case_id,
                    "call_id": call_id,
                    "tool": tool,
                    "args": args,
                    "tier": tool_policy.tier.value,
                    "order_id": order.order_id if order else None,
                    "order_hash": order.order_hash if order else None,
                },
                self.policy.policy_hash,
            )
        except AuditWriteError as exc:
            return deny(DenialReason.AUDIT_WRITE_FAILED, str(exc))

        # -- 9. execute, with retry for reads only -------------------------
        is_write = tool_policy.tier is Tier.WRITE
        attempts = 1 if is_write else self.max_retries
        last_error = ""
        payload: Any = None
        succeeded = False
        used_attempts = 0
        started = time.monotonic()

        for attempt in range(attempts):
            used_attempts = attempt + 1
            if attempt:
                # Each retry costs budget, so failures cannot be looped for free.
                retry = self.budget.reserve(scope, calls=1)
                if not retry.ok:
                    self.budget.reconcile(reservation, seconds_used=time.monotonic() - started)
                    return deny(
                        DenialReason.BUDGET_EXHAUSTED,
                        f"retry budget exhausted after {attempt} attempt(s): {retry.reason}",
                        stop=StopReason.BUDGET_EXHAUSTED,
                    )
                self._sleep(self.backoff_seconds[min(attempt - 1, len(self.backoff_seconds) - 1)])
            try:
                call_started = time.monotonic()
                payload = self._invoke(tool, args)
                elapsed = time.monotonic() - call_started
                if elapsed > self.tool_timeout_seconds:
                    raise ToolTimeout(f"{tool} took {elapsed:.1f}s")
                last_error = ""
                succeeded = True
                break
            except DroppedResponse as exc:
                last_error = str(exc)
                if is_write:
                    self.budget.reconcile(reservation, seconds_used=time.monotonic() - started)
                    return deny(
                        DenialReason.TOOL_FAILURE,
                        f"write response lost: {exc}",
                        stop=StopReason.TIMEOUT,
                        response_unknown=True,
                    )
            except (ToolTimeout, ToolError) as exc:
                last_error = str(exc)
                payload = None
            except MalformedToolOutput as exc:
                # The tool itself broke its contract. Not transient; do not retry.
                self.budget.reconcile(reservation, seconds_used=time.monotonic() - started)
                return deny(
                    DenialReason.MALFORMED_OUTPUT, str(exc), stop=StopReason.MALFORMED_OUTPUT
                )
            except Exception as exc:  # unexpected: fail closed and escalate
                self._alert(
                    "UNEXPECTED_ERROR", {"case_id": case_id, "tool": tool, "error": str(exc)}
                )
                self.budget.reconcile(reservation, seconds_used=time.monotonic() - started)
                return deny(
                    DenialReason.TOOL_FAILURE,
                    f"unexpected error: {exc}",
                    stop=StopReason.TOOL_FAILURE,
                )

        total_elapsed = time.monotonic() - started
        self.budget.reconcile(reservation, seconds_used=total_elapsed)

        if not succeeded:
            return deny(
                DenialReason.TOOL_FAILURE,
                last_error or "tool returned nothing",
                stop=StopReason.TOOL_FAILURE,
            )

        # -- 10. output schema -------------------------------------------
        bad = validate_output(tool, payload)
        if bad:
            # Discarded, not repaired and not partially used.
            return deny(
                DenialReason.MALFORMED_OUTPUT,
                bad,
                stop=StopReason.MALFORMED_OUTPUT,
            )

        # -- 11. store raw output by hash ---------------------------------
        raw_hash = self.raw.put(tool, payload)

        # -- 12. attach trust labels from policy --------------------------
        records = payload if isinstance(payload, list) else [payload]
        try:
            labeled: list[LabeledRecord] = [
                self.ledger.label_record(
                    source_tool=tool, record=rec, raw_hash=raw_hash, case_id=case_id
                )
                for rec in records
                if isinstance(rec, dict)
            ]
        except TrustUpgradeError as exc:
            self._alert("TRUST_UPGRADE_ATTEMPT", {"case_id": case_id, "error": str(exc)})
            return deny(DenialReason.POLICY_TAMPERED, str(exc), stop=StopReason.POLICY_TAMPERED)

        # -- 13. log the result -------------------------------------------
        untrusted_fields = sorted(
            {
                name
                for rec in labeled
                for name, lv in rec.fields.items()
                if lv.trust is Trust.UNTRUSTED
            }
        )
        try:
            result_entry = self.audit.append(
                EventType.TOOL_RESULT,
                caller,
                {
                    "case_id": case_id,
                    "call_id": call_id,
                    "tool": tool,
                    "raw_hash": raw_hash,
                    "records": len(labeled),
                    "record_ids": [r.record_id for r in labeled],
                    "untrusted_fields": untrusted_fields,
                    "elapsed_seconds": round(total_elapsed, 4),
                    "attempts": used_attempts,
                },
                self.policy.policy_hash,
            )
        except AuditWriteError as exc:
            return deny(DenialReason.AUDIT_WRITE_FAILED, str(exc))

        return ToolResult(
            call_id=call_id,
            tool=tool,
            raw_hash=raw_hash,
            records=labeled,
            log_entry_id=result_entry.entry_id,
            elapsed_seconds=round(total_elapsed, 4),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _invoke(self, tool: str, args: dict[str, Any]) -> Any:
        fn = getattr(self.tools, tool, None)
        if fn is None or tool not in self.policy.tools:
            raise MalformedToolOutput(f"no implementation for tool {tool!r}")
        return fn(**args)

    def _policy_intact(self) -> bool:
        try:
            return compute_policy_hash(self.policy_path) == self.policy.policy_hash
        except OSError:
            return False  # cannot check -> fail closed

    def _alert(self, kind: str, payload: dict) -> None:
        try:
            self.audit.append(
                EventType.ALERT, "gateway", {"alert": kind, **payload}, self.policy.policy_hash
            )
        except AuditWriteError:
            pass

    def client_for(self, order: WorkOrder) -> "GatewayClient":
        return GatewayClient(self, caller=order.worker_role, case_id=order.case_id, order=order)

    def executor_client(self, case_id: str) -> "GatewayClient":
        return GatewayClient(self, caller=EXECUTOR, case_id=case_id, order=None)


class GatewayClient:
    """The entire world a worker can see.

    A worker is handed one of these and nothing else - no tool module, no
    database handle, no credentials. ``tests/unit/test_worker_isolation.py``
    enforces that by inspecting ``agents/worker.py``'s imports.
    """

    def __init__(
        self,
        gateway: Gateway,
        *,
        caller: str,
        case_id: str,
        order: WorkOrder | None,
    ) -> None:
        self._gateway = gateway
        self.caller = caller
        self.case_id = case_id
        self.order = order

    def call(self, tool: str, **args: Any) -> GatewayOutcome:
        return self._gateway.call(
            caller=self.caller,
            tool=tool,
            args=args,
            case_id=self.case_id,
            order=self.order,
        )

    @property
    def allowed_tools(self) -> list[str]:
        return list(self.order.allowed_tools) if self.order else []

    def budget_remaining(self):
        return self._gateway.budget.remaining(self.caller)

    def budget_exhausted(self) -> bool:
        return not self._gateway.budget.reserve_dry_run(self.caller).ok

    def charge_tokens(self, tokens: int) -> bool:
        """Bill an LLM call to this worker's token budget.

        Returns False when the charge would breach the ceiling, which the
        worker treats as a stop condition. Tokens are metered the same way
        tool calls are, so a worker cannot loop on reasoning for free either.
        """
        return self._gateway.budget.reserve(self.caller, calls=0, tokens=tokens).ok
