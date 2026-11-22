"""Budget metering: calls, tokens and seconds, per worker and globally.

Reserve-before-call, reconcile-after. Reserving first is what makes the bound
hold under failure: a call that times out, errors or returns garbage has
already consumed its allowance, so a worker cannot loop for free on failures.
Each retry reserves again, per the PRD.

Two scopes are checked on every reservation - the worker's own budget and the
case-wide budget - and the tighter one wins.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core.models import Budget, BudgetUsage

GLOBAL = "__global__"


@dataclass
class _Account:
    budget: Budget
    calls: int = 0
    tokens: int = 0
    seconds: float = 0.0
    started: float = field(default_factory=time.monotonic)

    def elapsed(self) -> float:
        return time.monotonic() - self.started


@dataclass(frozen=True)
class Reservation:
    scope: str
    calls: int
    tokens: int
    started_at: float


@dataclass(frozen=True)
class BudgetDecision:
    ok: bool
    reason: str = ""
    scope: str = ""
    reservation: Reservation | None = None


class BudgetMeter:
    """Tracks spend against a per-scope and a global ceiling."""

    def __init__(self, global_budget: Budget) -> None:
        self._accounts: dict[str, _Account] = {GLOBAL: _Account(global_budget)}

    # -- registration ------------------------------------------------------

    def register(self, scope: str, budget: Budget) -> None:
        self._accounts[scope] = _Account(budget)

    def known(self, scope: str) -> bool:
        return scope in self._accounts

    # -- reserve / reconcile ----------------------------------------------

    def reserve(self, scope: str, *, calls: int = 1, tokens: int = 0) -> BudgetDecision:
        """Claim allowance before a call. Fails closed on an unknown scope."""
        acct = self._accounts.get(scope)
        if acct is None:
            return BudgetDecision(
                ok=False, reason=f"no budget registered for {scope!r}", scope=scope
            )
        for name, a in ((scope, acct), (GLOBAL, self._accounts[GLOBAL])):
            if a.calls + calls > a.budget.calls:
                return BudgetDecision(
                    ok=False,
                    scope=name,
                    reason=f"{name}: call budget exhausted "
                    f"({a.calls}/{a.budget.calls})",
                )
            if a.tokens + tokens > a.budget.tokens:
                return BudgetDecision(
                    ok=False,
                    scope=name,
                    reason=f"{name}: token budget exhausted "
                    f"({a.tokens}/{a.budget.tokens})",
                )
            if a.elapsed() > a.budget.seconds:
                return BudgetDecision(
                    ok=False,
                    scope=name,
                    reason=f"{name}: time budget exhausted "
                    f"({a.elapsed():.1f}s/{a.budget.seconds}s)",
                )
        acct.calls += calls
        acct.tokens += tokens
        g = self._accounts[GLOBAL]
        g.calls += calls
        g.tokens += tokens
        return BudgetDecision(
            ok=True,
            scope=scope,
            reservation=Reservation(scope, calls, tokens, time.monotonic()),
        )

    def reconcile(
        self, reservation: Reservation, *, tokens_used: int = 0, seconds_used: float | None = None
    ) -> None:
        """Settle a reservation against what the call actually cost.

        Only ever adjusts upward for tokens: the reservation is a floor, not a
        refund. Under-reserving must not let a caller exceed the ceiling, so any
        excess is charged here and the next reserve() sees it.
        """
        acct = self._accounts.get(reservation.scope)
        if acct is None:
            return
        elapsed = (
            seconds_used
            if seconds_used is not None
            else time.monotonic() - reservation.started_at
        )
        extra = max(0, tokens_used - reservation.tokens)
        acct.tokens += extra
        acct.seconds += elapsed
        g = self._accounts[GLOBAL]
        g.tokens += extra
        g.seconds += elapsed

    # -- reporting ---------------------------------------------------------

    def usage(self, scope: str) -> BudgetUsage:
        acct = self._accounts.get(scope)
        if acct is None:
            return BudgetUsage()
        return BudgetUsage(
            calls=acct.calls, tokens=acct.tokens, seconds=round(acct.seconds, 3)
        )

    def budget_of(self, scope: str) -> Budget | None:
        acct = self._accounts.get(scope)
        return acct.budget if acct else None

    def remaining(self, scope: str) -> Budget | None:
        acct = self._accounts.get(scope)
        if acct is None:
            return None
        return Budget(
            calls=max(0, acct.budget.calls - acct.calls),
            tokens=max(0, acct.budget.tokens - acct.tokens),
            seconds=max(0, int(acct.budget.seconds - acct.elapsed())),
        )

    def exhausted(self, scope: str) -> bool:
        return not self.reserve_dry_run(scope).ok

    def reserve_dry_run(self, scope: str, *, calls: int = 1) -> BudgetDecision:
        """Check without consuming, for stop-condition tests."""
        acct = self._accounts.get(scope)
        if acct is None:
            return BudgetDecision(ok=False, reason="unknown scope", scope=scope)
        g = self._accounts[GLOBAL]
        for name, a in ((scope, acct), (GLOBAL, g)):
            if a.calls + calls > a.budget.calls:
                return BudgetDecision(ok=False, scope=name, reason="call budget exhausted")
            if a.elapsed() > a.budget.seconds:
                return BudgetDecision(ok=False, scope=name, reason="time budget exhausted")
        return BudgetDecision(ok=True, scope=scope)

    def scopes(self) -> list[str]:
        return [s for s in self._accounts if s != GLOBAL]
