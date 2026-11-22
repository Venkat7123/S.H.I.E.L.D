"""Streamlit UI - exactly two pages, as the PRD fixes.

1. **Case run + approval** - orders, evidence with trust colours, the
   disagreement report, and the approval panel.
2. **Audit log + attack results** - the log table, a verify button, and the
   scenario results.

The approval panel calls the same ``ApprovalGate`` the CLI does. There is one
approval path in the system; this is a different button on it, not a second
implementation.

Run with:  ``streamlit run ui/app.py``
"""

from __future__ import annotations

import html
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.approval import ApprovalPresentation  # noqa: E402
from core.audit_log import AuditLog, demo_tamper_entry  # noqa: E402
from core.db import DEFAULT_DB  # noqa: E402
from core.models import CaseStatus, Trust, Verdict  # noqa: E402
from data.seed import seed as seed_db  # noqa: E402
from harness.runner import CaseRunner, RunOptions  # noqa: E402
from harness.scenarios import ORDER, run_all  # noqa: E402

DB = DEFAULT_DB
JSONL = "logs/audit.jsonl"

TRUSTED_BG = "#1b5e20"
UNTRUSTED_BG = "#9a4b00"

st.set_page_config(page_title="S.H.I.E.L.D", page_icon="🛡️", layout="wide")


def chip(text: str, trust: Trust) -> str:
    bg = TRUSTED_BG if trust is Trust.TRUSTED else UNTRUSTED_BG
    return (
        f"<span style='background:{bg};color:#fff;padding:2px 8px;"
        f"border-radius:10px;font-size:0.8em;font-weight:600'>{html.escape(text)}</span>"
    )


def safe(value: object) -> str:
    """Escape a value an LLM chose before it reaches HTML-enabled markdown.

    A proposed target is a string the supervisor picked, and the supervisor is
    untrusted-zone code. The pages that colour-code trust use
    ``unsafe_allow_html`` to draw the chips, so an unescaped model-chosen value
    could draw its own - forging the exact signal the operator is reading.
    """
    return html.escape(str(value))


# --------------------------------------------------------------------------
# Page 1
# --------------------------------------------------------------------------


def page_case_run() -> None:
    st.title("🛡️ S.H.I.E.L.D — case run and approval")
    st.caption(
        "The AI does the thinking. Deterministic code outside the model does the controlling."
    )

    col1, col2, col3 = st.columns([2, 2, 1])
    case_id = col1.selectbox("Case", ["CASE-001", "CASE-002", "CASE-003"])
    optional = col2.checkbox("Enable optional checks (independent sources, missed action)")
    if col3.button("Re-seed bank"):
        for suffix in ("", "-wal", "-shm"):
            Path(DB + suffix).unlink(missing_ok=True)
        Path(JSONL).unlink(missing_ok=True)
        seed_db(DB)
        st.session_state.pop("report", None)
        st.success("Mock bank re-seeded.")

    st.divider()

    if st.button("Run case", type="primary"):
        _run_case(case_id, optional)

    report = st.session_state.get("report")
    if report is None:
        st.info("Run a case to see work orders, evidence and the approval panel.")
        _guarantees()
        return

    _render_report(report)
    _guarantees()


def _run_case(case_id: str, optional: bool) -> None:
    """Run up to the approval point, holding the decision for the human."""
    pending: dict = {}

    def capture(presentation: ApprovalPresentation) -> tuple[str, str]:
        pending["presentation"] = presentation
        decision = st.session_state.get("pending_decision")
        if decision is None:
            # No decision yet. Refuse, and show the panel so the operator can
            # approve on the next run. Fail closed: no decision means no action.
            return "REJECTED", "awaiting-approver"
        return decision, "streamlit-approver"

    runner = CaseRunner(RunOptions(db_path=DB, jsonl_path=JSONL, enable_optional_checks=optional))
    try:
        report = runner.run(case_id, decider=capture)
        st.session_state["report"] = report
        st.session_state["presentation"] = pending.get("presentation")
        st.session_state["missed_action"] = runner.missed_action
        st.session_state["chain"] = runner.audit.verify_chain()
    finally:
        runner.close()


def _render_report(report) -> None:
    status_colour = {
        CaseStatus.COMPLETE: "✅",
        CaseStatus.PARTIAL: "⚠️",
        CaseStatus.ESCALATED: "🚨",
        CaseStatus.FAILED: "❌",
        CaseStatus.RUNNING: "…",
    }[report.status]
    st.subheader(f"{status_colour} {report.case_id} — {report.status.value}")

    # -- work orders ----------------------------------------------------
    st.markdown("### Work orders")
    st.caption(
        "Issued before any untrusted data was read, then frozen. "
        "Every field is covered by `order_hash`."
    )
    st.dataframe(
        [
            {
                "role": w.worker_role,
                "status": w.status,
                "stop reason": w.stop_reason.value,
                "calls": w.usage.calls,
                "tokens": w.usage.tokens,
                "missing": ", ".join(w.missing) or "—",
            }
            for w in report.workers
        ],
        width="stretch",
        hide_index=True,
    )

    # -- evidence -------------------------------------------------------
    st.markdown("### Evidence")
    st.markdown(
        f"{chip('TRUSTED', Trust.TRUSTED)} system of record &nbsp;&nbsp; "
        f"{chip('UNTRUSTED', Trust.UNTRUSTED)} free text, may be hostile",
        unsafe_allow_html=True,
    )
    for pack in report.packs:
        with st.expander(f"{pack.order_id} — {pack.status} ({len(pack.evidence_items)} items)"):
            for item in pack.evidence_items:
                st.markdown(
                    f"{chip(item.trust.value.upper(), item.trust)} "
                    f"**{item.item_id}** · `{item.source_system}` · "
                    f"raw `{item.raw_hash[:16]}…`",
                    unsafe_allow_html=True,
                )
                st.code(", ".join(item.record_refs), language=None)
            if pack.assumptions:
                st.caption("assumptions: " + ", ".join(a.value for a in pack.assumptions))

    # -- disagreement ---------------------------------------------------
    st.markdown("### Claim comparison")
    st.caption("Built in code. Never averaged, never resolved by a model.")
    rows = []
    for g in report.comparison.groups:
        icon = {"AGREE": "🟢", "CONFLICT": "🔴", "SINGLE": "🟡"}[g.verdict.value]
        rows.append(
            {
                "": icon,
                "subject": g.subject,
                "predicate": g.predicate.value,
                "verdict": g.verdict.value,
                "asserted by": ", ".join(f"{c.worker_role} ({c.confidence})" for c in g.asserted)
                or "—",
                "denied by": ", ".join(f"{c.worker_role} ({c.confidence})" for c in g.denied)
                or "—",
                "trusted sources": g.independent_trusted_sources,
            }
        )
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.caption("No claims were made.")

    # -- escalation -----------------------------------------------------
    if report.escalations:
        st.error("**Escalated to a human — the write path is closed for this case.**")
        for n in report.escalations:
            st.markdown(f"- `{n.trigger.value}` ({n.log_entry_id}) — {n.detail}")

    # -- approval -------------------------------------------------------
    st.markdown("### Approval")
    presentation = st.session_state.get("presentation")
    if presentation is None:
        if report.proposal:
            trust = report.proposal.target.trust
            st.markdown(
                f"Supervisor proposed **{report.proposal.action.value}** on "
                f"**{safe(report.proposal.target.value)}** "
                f"{chip(trust.value.upper(), trust)}",
                unsafe_allow_html=True,
            )
            st.caption(f"origin: {report.proposal.target.source_record}")
        if report.action:
            if report.action.executed:
                st.success(f"Executed. {report.action.detail}")
            else:
                st.warning(
                    f"Refused: **{report.action.stop_reason.value}** — {report.action.detail}"
                )
        else:
            st.info("No action reached the approval stage.")
    else:
        _approval_panel(presentation, report)

    missed = st.session_state.get("missed_action")
    if missed is not None and missed.missed:
        st.warning(f"**MISSED_ACTION** — {missed.detail}")

    if report.ai_summary:
        st.markdown("### AI-written summary")
        st.caption("Not evidence. Never read by the executor. Shown last on purpose.")
        # st.text, not st.info: a summary is model output, and rendering it as
        # markdown would let it draw links, images or headings of its own.
        st.text(report.ai_summary)


def _approval_panel(presentation: ApprovalPresentation, report) -> None:
    req = presentation.request
    st.markdown(f"#### {req.action.value} → `{safe(req.target)}`")
    c1, c2 = st.columns(2)
    c1.metric("account state now", req.account_state.value)
    c2.metric("approval window", f"{req.ttl_seconds}s, single use")
    st.code(f"action_hash  {req.action_hash}\npolicy_hash  {req.policy_hash}", language=None)
    st.caption(
        "The account state is part of the action hash. If it changes before the "
        "write, the approval no longer matches and the executor refuses."
    )

    if presentation.trusted_evidence:
        st.markdown(f"{chip('TRUSTED evidence', Trust.TRUSTED)}", unsafe_allow_html=True)
        st.dataframe(presentation.trusted_evidence, width="stretch", hide_index=True)
    if presentation.disagreements:
        st.markdown("**Disagreements**")
        st.dataframe(presentation.disagreements, width="stretch", hide_index=True)
    if presentation.untrusted_items:
        st.markdown(
            f"{chip('UNTRUSTED items', Trust.UNTRUSTED)} — shown for context, "
            "not evidence for this action",
            unsafe_allow_html=True,
        )
        st.dataframe(presentation.untrusted_items, width="stretch", hide_index=True)
    if presentation.ai_summary:
        st.caption("AI-written summary — not evidence")
        st.text(presentation.ai_summary)

    st.caption(
        "Approving re-runs the case with your decision in place, so the approval is "
        "given against freshly gathered evidence rather than a cached screen. The "
        "idempotency store still allows at most one execution of this action."
    )
    col1, col2 = st.columns(2)
    if col1.button("Approve", type="primary"):
        st.session_state["pending_decision"] = "APPROVED"
        _run_case(report.case_id, False)
        st.session_state.pop("pending_decision", None)
        st.rerun()
    if col2.button("Reject"):
        st.session_state["pending_decision"] = "REJECTED"
        _run_case(report.case_id, False)
        st.session_state.pop("pending_decision", None)
        st.rerun()


def _guarantees() -> None:
    st.divider()
    st.markdown("### What this guarantees — and what it does not")
    left, right = st.columns(2)
    left.success(
        "**Guaranteed (enforced by code, tested)**\n\n"
        "Even if every worker and the supervisor are attacker-controlled:\n\n"
        "1. No agent can call a tool outside its order, or any write tool.\n"
        "2. No worker or case exceeds its call, token or time budget.\n"
        "3. At most one execution per approved action, given state can be read back.\n"
        "4. An approval binds one action **and one account state**; single-use; expiring.\n"
        "5. A freeze target and the threshold need TRUSTED fields from systems of record.\n"
        "6. An escalated case never reaches the write path.\n"
        "7. Editing any log entry is detected by `verify_chain()`."
    )
    right.warning(
        "**Not guaranteed**\n\n"
        "1. It does not stop prompt injection — it limits what a hijacked agent can do.\n"
        "2. Conclusions can still be wrong; agents can mislead within the schema.\n"
        "3. Lies planted across several systems of record can mislead it.\n"
        "4. A tricked supervisor may fail to propose a needed freeze.\n"
        "5. Whole-log rewrite or tail deletion by someone with full machine access "
        "is not detected. Entry edits are.\n"
        "6. If the trusted core is compromised, the guarantees fail.\n"
        "7. A careless human can still approve a bad action."
    )


# --------------------------------------------------------------------------
# Page 2
# --------------------------------------------------------------------------


def page_audit_and_attacks() -> None:
    st.title("🛡️ S.H.I.E.L.D — audit log and attack results")

    st.markdown("### Audit log")
    log = AuditLog(DB, JSONL)
    try:
        entries = log.entries()
        c1, c2, c3 = st.columns([1, 1, 2])
        if c1.button("Verify chain", type="primary"):
            result = log.verify_chain()
            if result.ok:
                st.success(f"Chain intact across {result.entries} entries.")
            else:
                st.error(
                    f"BROKEN at entry {result.first_broken_index}: {result.detail}"
                )
        tamper_index = c2.number_input(
            "entry", min_value=0, max_value=max(0, len(entries) - 1), value=min(7, max(0, len(entries) - 1))
        )
        if c3.button("Tamper with this entry (demo only)"):
            log.close()
            demo_tamper_entry(DB, int(tamper_index))
            st.warning(
                f"Entry {int(tamper_index)} edited. Press **Verify chain** to see it caught."
            )
            st.rerun()

        st.dataframe(
            [
                {
                    "#": e.index,
                    "event": e.event_type.value,
                    "actor": e.actor,
                    "case": e.payload.get("case_id", "—"),
                    "summary": _summarise(e),
                    "entry_hash": e.entry_hash[:16] + "…",
                }
                for e in entries
            ],
            width="stretch",
            hide_index=True,
            height=420,
        )
        st.caption(
            f"{len(entries)} entries. Append-only in storage; UPDATE and DELETE "
            "are refused by database triggers. Personal data is masked before hashing."
        )
    finally:
        try:
            log.close()
        except Exception:
            pass

    st.divider()
    st.markdown("### Attack scenarios")
    st.caption(f"{len(ORDER)} scenarios, each from a freshly seeded bank. Results are recorded as they come.")
    if st.button("Run all scenarios"):
        with st.spinner("Running 12 scenarios…"):
            st.session_state["scenarios"] = run_all("data/scenarios.db")

    results = st.session_state.get("scenarios")
    if results:
        passed = sum(1 for r in results if r.passed)
        (st.success if passed == len(results) else st.error)(
            f"{passed}/{len(results)} scenarios passed"
        )
        st.dataframe(
            [
                {
                    "": "✅" if r.passed else "❌",
                    "id": r.id,
                    "scenario": r.title,
                    "expected": r.expected,
                    "actual": r.actual,
                    "detail": r.detail,
                }
                for r in results
            ],
            width="stretch",
            hide_index=True,
            height=460,
        )


def _summarise(entry) -> str:
    p = entry.payload
    event = entry.event_type.value
    if event == "TOOL_CALL":
        return f"{p.get('tool')} {p.get('args', {})}"
    if event == "TOOL_RESULT":
        return f"{p.get('tool')} → {p.get('records')} records, untrusted: {p.get('untrusted_fields')}"
    if event == "DENIAL":
        return f"{p.get('reason')}: {p.get('detail', '')[:80]}"
    if event == "ORDER":
        return f"{p.get('role')} tools={p.get('allowed_tools')}"
    if event == "PROPOSAL":
        return f"{p.get('action')} {p.get('target')} ({p.get('target_trust')})"
    if event == "APPROVAL":
        return f"{p.get('decision')} by {p.get('approver')}"
    if event == "ACTION":
        return f"{p.get('state')} {p.get('target', '')}"
    if event == "ALERT":
        return f"{p.get('alert')}: {str(p.get('detail', ''))[:80]}"
    if event == "STOP":
        return f"{p.get('status')} {p.get('stop_reasons', '')}"
    if event == "DECISION":
        return str({k: v for k, v in p.items() if k != "case_id"})[:100]
    return ""


# --------------------------------------------------------------------------

PAGES = {
    "Case run + approval": page_case_run,
    "Audit log + attacks": page_audit_and_attacks,
}

choice = st.sidebar.radio("Page", list(PAGES))
st.sidebar.divider()
st.sidebar.caption(
    "Stub mode: offline, deterministic, identical on every run.\n\n"
    "`shield attack all` runs the same scenarios in the terminal."
)
PAGES[choice]()
