"""Comparing claims across workers - in code, never in a model.

Three rules, and the third is the point of the module:

1. Group claims by ``(subject, predicate)``. The predicate vocabulary is a
   closed enum, which is what makes grouping possible at all.
2. Label each group ``AGREE``, ``CONFLICT`` or ``SINGLE``.
3. **Never average, never pick a winner, never hide a side.** A conflict is
   reported as a conflict, with both sides' evidence, and the case escalates.

Asking a model to reconcile disagreement is how disagreement disappears: it
produces a confident paragraph and the fact that two investigators saw
different things is gone. A conflict is information, and it belongs in front of
the human.

``SINGLE`` is deliberately distinct from ``AGREE``. One worker asserting
something unopposed is not corroboration, and the report should not let it look
like it.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

from core.models import (
    Claim,
    ClaimGroup,
    ClaimRef,
    ComparisonReport,
    EvidenceItem,
    EvidencePack,
    Trust,
    Verdict,
)

# Which system of record each tool speaks for.
_TOOL_SYSTEM = {
    "query_transactions": "transactions_db",
    "read_case_notes": "notes_store",
}


def compare(
    packs: list[EvidencePack], roles: dict[str, str] | None = None
) -> ComparisonReport:
    """Build the disagreement report.

    ``roles`` maps ``order_id`` to worker role, so the report can say *who*
    claimed what without the claim itself carrying free text.
    """
    roles = roles or {}
    items: dict[str, tuple[EvidenceItem, str]] = {}
    for pack in packs:
        for item in pack.evidence_items:
            items[item.item_id] = (item, pack.order_id)

    grouped: dict[tuple[str, str], list[tuple[Claim, EvidencePack]]] = {}
    for pack in packs:
        if pack.status == "FAILED":
            # A failed pack contributes no claims. Its stop reason is reported
            # separately in the case report, not folded in as a finding.
            continue
        for claim in pack.claims:
            grouped.setdefault((claim.subject, claim.predicate.value), []).append((claim, pack))

    groups: list[ClaimGroup] = []
    for (subject, predicate), entries in sorted(grouped.items()):
        asserted: list[ClaimRef] = []
        denied: list[ClaimRef] = []
        systems: set[str] = set()

        for claim, pack in entries:
            cited = list(claim.evidence_for) + list(claim.evidence_against)
            trusted_systems = sorted(
                {
                    _TOOL_SYSTEM.get(items[i][0].source_tool, "unknown")
                    for i in cited
                    if i in items and items[i][0].trust is Trust.TRUSTED
                }
            )
            systems.update(trusted_systems)
            ref = ClaimRef(
                claim_id=claim.claim_id,
                order_id=pack.order_id,
                worker_role=roles.get(pack.order_id, pack.order_id),
                value=claim.value,
                confidence=claim.confidence,
                evidence_item_ids=cited,
                trusted_sources=trusted_systems,
            )
            (asserted if claim.value else denied).append(ref)

        if asserted and denied:
            verdict = Verdict.CONFLICT
        elif len(entries) == 1:
            verdict = Verdict.SINGLE
        else:
            verdict = Verdict.AGREE

        groups.append(
            ClaimGroup(
                subject=subject,
                predicate=entries[0][0].predicate,
                verdict=verdict,
                asserted=asserted,
                denied=denied,
                independent_trusted_sources=len(systems),
            )
        )

    return ComparisonReport(groups=groups)


def summarise(report: ComparisonReport) -> dict:
    """Counts for the case report and the CLI table. No interpretation."""
    return {
        "groups": len(report.groups),
        "agree": sum(1 for g in report.groups if g.verdict is Verdict.AGREE),
        "conflict": len(report.conflicts),
        "single": sum(1 for g in report.groups if g.verdict is Verdict.SINGLE),
        "conflicting_predicates": sorted(
            f"{g.subject}/{g.predicate.value}" for g in report.conflicts
        ),
    }
