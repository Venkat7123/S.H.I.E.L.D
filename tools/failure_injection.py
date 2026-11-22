"""Deterministic fault injection for the tool layer.

Scenarios A4b and A8 need tools that time out, error, return garbage, or - the
nastiest one - *succeed on the server and lose the response*. Real systems do
all four, and each exercises a different control:

=================  ===========================================================
``delay_seconds``  pushes the call past its timeout -> retry path
``raise_error``    transient error -> retry path, then ``TOOL_FAILURE``
``malformed``      output that fails schema validation -> discarded, not used
``drop_response``  **the write lands, the caller never hears** -> read-back
=================  ===========================================================

``drop_response`` is the one that justifies idempotency. Without read-back
before retry, that is how an account gets frozen twice.

Faults are armed per tool and consumed in order, so a run is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Fault:
    delay_seconds: float = 0.0
    raise_error: bool = False
    drop_response: bool = False
    malformed: bool = False
    message: str = "injected fault"

    @property
    def is_noop(self) -> bool:
        return not (
            self.delay_seconds or self.raise_error or self.drop_response or self.malformed
        )


@dataclass
class FailureInjector:
    """A queue of faults per tool name. Empty queue means healthy."""

    queues: dict[str, list[Fault]] = field(default_factory=dict)
    consumed: list[tuple[str, Fault]] = field(default_factory=list)

    def arm(self, tool: str, fault: Fault, times: int = 1) -> "FailureInjector":
        self.queues.setdefault(tool, []).extend([fault] * times)
        return self

    def next_fault(self, tool: str) -> Fault | None:
        queue = self.queues.get(tool)
        if not queue:
            return None
        fault = queue.pop(0)
        self.consumed.append((tool, fault))
        return fault

    def pending(self, tool: str) -> int:
        return len(self.queues.get(tool, []))

    def clear(self) -> None:
        self.queues.clear()
        self.consumed.clear()


class DroppedResponse(Exception):
    """The tool did its work; the caller never received the answer.

    Indistinguishable from a timeout at the call site - which is the point.
    """
