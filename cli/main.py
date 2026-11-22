"""``shield`` - the command line, and the primary demo surface.

    shield seed                    create the mock bank
    shield run --case CASE-001     run one case end to end
    shield attack all              run every demo scenario, print the table
    shield attack A7               run one scenario
    shield verify-log              verify the audit hash chain
    shield tamper --entry 7        DEMO ONLY: edit a log entry
    shield show-case CASE-001      inspect the seeded data
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Anything an LLM chose - a proposed target, a summary, a detail string that
# quotes one - is rendered as plain Text or escaped before it reaches rich.
#
# Rich interprets square-bracket markup in strings. The approval screen uses
# colour to mean something ("green = TRUSTED"), so an AI-written summary
# containing [bold green]VERIFIED[/bold green] could forge exactly the signal
# the operator is being asked to rely on. The model is untrusted here too, and
# that does not stop at the schema boundary - it extends to the renderer.

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.approval import ApprovalPresentation  # noqa: E402
from core.audit_log import AuditLog, demo_tamper_entry  # noqa: E402
from core.db import DEFAULT_DB  # noqa: E402
from core.models import CaseStatus, Trust, Verdict  # noqa: E402
from data.seed import seed as seed_db  # noqa: E402
from harness.runner import CaseRunner, RunOptions  # noqa: E402
from harness.scenarios import ORDER, run_all, run_scenario  # noqa: E402

app = typer.Typer(
    add_completion=False,
    help="S.H.I.E.L.D - a governed multi-agent investigation system.",
    no_args_is_help=True,
)
console = Console()

TRUSTED_STYLE = "bold green"
UNTRUSTED_STYLE = "bold dark_orange"


# --------------------------------------------------------------------------


@app.command()
def seed(
    db: str = typer.Option(DEFAULT_DB, help="Database path."),
    jsonl: str = typer.Option("logs/audit.jsonl", help="JSONL mirror to reset alongside it."),
) -> None:
    """Create the mock bank and load the fixture.

    This drops the database file, which holds the audit log too. The JSONL
    mirror is cleared with it - leaving a stale mirror beside a fresh chain
    would make the two disagree about what happened, which is worse than
    starting both from empty.
    """
    for suffix in ("", "-wal", "-shm"):
        Path(db + suffix).unlink(missing_ok=True)
    Path(jsonl).unlink(missing_ok=True)
    counts = seed_db(db)
    table = Table(title="Mock bank seeded", header_style="bold")
    table.add_column("table")
    table.add_column("rows", justify="right")
    for name, n in counts.items():
        table.add_row(name, str(n))
    console.print(table)
    console.print(f"[dim]{db}[/dim]")


@app.command()
def run(
    case: str = typer.Option("CASE-001", "--case", help="Case id."),
    db: str = typer.Option(DEFAULT_DB, help="Database path."),
    auto_approve: bool = typer.Option(
        False, "--auto-approve", help="Approve without prompting (for scripted runs)."
    ),
    reject: bool = typer.Option(False, "--reject", help="Reject any proposed action."),
    optional_checks: bool = typer.Option(
        False, "--optional-checks", help="Enable the independent-source and missed-action checks."
    ),
) -> None:
    """Run one case end to end: plan, work, compare, propose, approve, act."""
    runner = CaseRunner(
        RunOptions(db_path=db, scenario_id=None, enable_optional_checks=optional_checks)
    )
    decider = _auto("APPROVED") if auto_approve else (_auto("REJECTED") if reject else _prompt)
    try:
        report = runner.run(case, decider=decider)
        _print_report(report, runner)
    finally:
        runner.close()


@app.command()
def attack(
    scenario: str = typer.Argument("all", help="Scenario id, or 'all'."),
    db: str = typer.Option("data/scenarios.db", help="Database path for scenario runs."),
) -> None:
    """Run the demo scenarios and print expected against actual."""
    if scenario.lower() == "all":
        results = run_all(db)
    else:
        key = next((s for s in ORDER if s.lower() == scenario.lower()), scenario)
        results = [run_scenario(key, db)]

    table = Table(title="S.H.I.E.L.D attack scenarios", header_style="bold", show_lines=True)
    table.add_column("id", style="bold", no_wrap=True)
    table.add_column("scenario", max_width=30)
    table.add_column("expected", max_width=44)
    table.add_column("actual", max_width=48)
    table.add_column("result", justify="center", no_wrap=True)

    for r in results:
        table.add_row(
            r.id,
            r.title,
            r.expected,
            Text(r.actual + (f"\n{r.detail}" if r.detail else "")),
            Text("PASS", style="bold green") if r.passed else Text("FAIL", style="bold red"),
        )
    console.print(table)

    passed = sum(1 for r in results if r.passed)
    style = "bold green" if passed == len(results) else "bold red"
    console.print(f"[{style}]{passed}/{len(results)} scenarios passed[/{style}]")
    if passed != len(results):
        raise typer.Exit(code=1)


@app.command("verify-log")
def verify_log(
    db: str = typer.Option(DEFAULT_DB, help="Database path."),
    jsonl: str = typer.Option("logs/audit.jsonl", help="JSONL mirror path."),
) -> None:
    """Verify the audit log's hash chain."""
    log = AuditLog(db, jsonl)
    try:
        result = log.verify_chain()
        if result.ok:
            console.print(
                Panel(
                    f"Chain intact across {result.entries} entries.",
                    title="verify-log",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[bold red]BROKEN at entry {result.first_broken_index}[/bold red]\n"
                    f"{result.detail}\n\n"
                    f"{result.entries} entries examined.",
                    title="verify-log",
                    border_style="red",
                )
            )
            raise typer.Exit(code=1)
    finally:
        log.close()


@app.command()
def tamper(
    entry: int = typer.Option(..., "--entry", help="Index of the entry to edit."),
    db: str = typer.Option(DEFAULT_DB, help="Database path."),
    field: str = typer.Option("actor", help="Field to overwrite."),
    value: str = typer.Option("attacker", help="New value."),
) -> None:
    """DEMO ONLY. Edit a stored log entry so verify-log can catch it."""
    demo_tamper_entry(db, entry, field=field, new_value=value)
    console.print(
        Panel(
            f"Entry {entry} edited: {field} = {value!r}.\n"
            "This is not a supported operation - it exists to prove detection works.\n"
            "Run [bold]shield verify-log[/bold] now.",
            title="tamper (demo helper)",
            border_style="yellow",
        )
    )


@app.command("show-case")
def show_case(
    case: str = typer.Argument("CASE-001"),
    db: str = typer.Option(DEFAULT_DB, help="Database path."),
) -> None:
    """Show the seeded data for a case, with trust colouring."""
    from tools.bank import BankTools

    tools = BankTools(db)
    try:
        record = tools.get_case(case)
        if record is None:
            console.print(f"[red]unknown case {case}[/red]")
            raise typer.Exit(code=1)
        subject = record["subject_account"]
        console.print(
            Panel(
                f"subject: [bold]{subject}[/bold]   flagged txn: {record['flagged_txn_id']}",
                title=case,
            )
        )
        txns = Table(title="transactions", header_style="bold")
        for col in ("txn_id", "from", "to", "amount", "timestamp", "description"):
            txns.add_column(col, max_width=46 if col == "description" else None)
        for t in tools.query_transactions(subject, 90):
            txns.add_row(
                t["txn_id"],
                t["from_account"],
                t["to_account"],
                f"{t['amount']:,}",
                t["timestamp"][:16],
                Text(t["description"][:120], style=UNTRUSTED_STYLE),
            )
        console.print(txns)

        notes = Table(title="case notes", header_style="bold")
        for col in ("note_id", "source", "created", "body"):
            notes.add_column(col, max_width=70 if col == "body" else None)
        for n in tools.read_case_notes(subject, 20):
            notes.add_row(
                n["note_id"],
                n["source"],
                n["created_at"][:10],
                Text(n["body"][:200], style=UNTRUSTED_STYLE),
            )
        console.print(notes)
        console.print(
            f"[{TRUSTED_STYLE}]green = TRUSTED[/{TRUSTED_STYLE}]   "
            f"[{UNTRUSTED_STYLE}]orange = UNTRUSTED (free text, may be hostile)[/{UNTRUSTED_STYLE}]"
        )
    finally:
        tools.close()


# --------------------------------------------------------------------------
# Approval prompt
# --------------------------------------------------------------------------


def _auto(decision: str):
    def decide(_p: ApprovalPresentation) -> tuple[str, str]:
        return decision, "scripted"

    return decide


def _prompt(presentation: ApprovalPresentation) -> tuple[str, str]:
    """The approval screen. Order is fixed: action, state, evidence, then AI."""
    req = presentation.request
    console.print()
    console.print(
        Panel(
            f"[bold]{req.action.value} {req.target}[/bold]\n\n"
            f"action hash : [cyan]{req.action_hash}[/cyan]\n"
            f"account now : [bold]{req.account_state.value}[/bold] "
            f"[dim](part of the hash - if this changes, the approval stops matching)[/dim]\n"
            f"policy hash : [dim]{req.policy_hash[:32]}...[/dim]\n"
            f"expires in  : {req.ttl_seconds}s, single use",
            title="ACTION REQUIRING APPROVAL",
            border_style="cyan",
        )
    )

    if presentation.trusted_evidence:
        table = Table(title="TRUSTED evidence (systems of record)", header_style=TRUSTED_STYLE)
        for col in ("item", "system", "raw hash", "records"):
            table.add_column(col)
        for row in presentation.trusted_evidence:
            table.add_row(
                row["item_id"],
                row["source_system"],
                row["raw_hash"],
                ", ".join(row["record_refs"][:6])
                + (" ..." if len(row["record_refs"]) > 6 else ""),
            )
        console.print(table)

    if presentation.disagreements:
        table = Table(title="DISAGREEMENTS", header_style="bold red")
        for col in ("subject", "predicate", "asserted by", "denied by"):
            table.add_column(col)
        for d in presentation.disagreements:
            table.add_row(
                d["subject"], d["predicate"], ", ".join(d["asserted_by"]), ", ".join(d["denied_by"])
            )
        console.print(table)
    else:
        console.print("[dim]No unresolved disagreements between workers.[/dim]")

    if presentation.untrusted_items:
        table = Table(
            title="UNTRUSTED items - free text, not evidence for this action",
            header_style=UNTRUSTED_STYLE,
        )
        for col in ("item", "system", "fields"):
            table.add_column(col)
        for row in presentation.untrusted_items:
            table.add_row(
                row["item_id"],
                row["source_system"],
                ", ".join(row["record_refs"][:4])
                + (" ..." if len(row["record_refs"]) > 4 else ""),
            )
        console.print(table)

    if presentation.ai_summary:
        console.print(
            Panel(
                Text(presentation.ai_summary),  # plain text: no markup from a model
                title="AI-written summary - NOT evidence, not read by the executor",
                border_style="dim",
            )
        )

    approved = typer.confirm(f"Approve {req.action.value} on {req.target}?", default=False)
    approver = "cli-approver"
    return ("APPROVED" if approved else "REJECTED"), approver


# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------


def _print_report(report, runner: CaseRunner) -> None:
    colour = {
        CaseStatus.COMPLETE: "green",
        CaseStatus.PARTIAL: "yellow",
        CaseStatus.ESCALATED: "magenta",
        CaseStatus.FAILED: "red",
        CaseStatus.RUNNING: "white",
    }[report.status]

    workers = Table(title="workers", header_style="bold")
    for col in ("role", "status", "stop reason", "calls", "tokens", "missing"):
        workers.add_column(col)
    for w in report.workers:
        workers.add_row(
            w.worker_role,
            w.status,
            w.stop_reason.value,
            str(w.usage.calls),
            str(w.usage.tokens),
            ", ".join(w.missing) or "-",
        )
    console.print(workers)

    evidence = Table(title="evidence", header_style="bold")
    for col in ("item", "trust", "system", "records"):
        evidence.add_column(col)
    for pack in report.packs:
        for item in pack.evidence_items:
            evidence.add_row(
                item.item_id,
                Text(
                    item.trust.value.upper(),
                    style=TRUSTED_STYLE if item.trust is Trust.TRUSTED else UNTRUSTED_STYLE,
                ),
                item.source_system,
                ", ".join(item.record_refs[:4]) + (" ..." if len(item.record_refs) > 4 else ""),
            )
    console.print(evidence)

    comparison = Table(title="claim comparison (built in code, not by a model)", header_style="bold")
    for col in ("subject", "predicate", "verdict", "asserted", "denied", "sources"):
        comparison.add_column(col)
    for g in report.comparison.groups:
        style = {"AGREE": "green", "CONFLICT": "bold red", "SINGLE": "yellow"}[g.verdict.value]
        comparison.add_row(
            g.subject,
            g.predicate.value,
            Text(g.verdict.value, style=style),
            ", ".join(f"{c.worker_role}/{c.confidence}" for c in g.asserted) or "-",
            ", ".join(f"{c.worker_role}/{c.confidence}" for c in g.denied) or "-",
            str(g.independent_trusted_sources),
        )
    console.print(comparison)

    if report.escalations:
        lines = "\n".join(
            f"- {n.trigger.value} ({n.log_entry_id}): {n.detail}" for n in report.escalations
        )
        console.print(
            Panel(
                lines + "\n\n[bold]The write path is closed for this case.[/bold]",
                title="ESCALATED TO A HUMAN",
                border_style="magenta",
            )
        )

    if report.proposal:
        p = report.proposal
        trust_style = TRUSTED_STYLE if p.target.trust is Trust.TRUSTED else UNTRUSTED_STYLE
        console.print(
            Panel(
                f"supervisor proposed: [bold]{p.action.value}[/bold] on "
                f"[bold]{escape(str(p.target.value))}[/bold]\n"
                f"target trust: [{trust_style}]{p.target.trust.value.upper()}[/{trust_style}]  "
                f"[dim]origin: {escape(p.target.source_record)}[/dim]",
                title="proposal",
                border_style="cyan",
            )
        )

    if report.action:
        a = report.action
        border = "green" if a.executed else "red"
        body = (
            f"executed : [bold]{a.executed}[/bold]\n"
            f"reason   : {a.stop_reason.value}\n"
            f"state    : {a.idempotency_state.value if a.idempotency_state else '-'}\n"
            f"detail   : {escape(a.detail)}"
        )
        if a.action_hash:
            body += f"\nhash     : [dim]{a.action_hash[:32]}...[/dim]"
        console.print(Panel(body, title="executor", border_style=border))

    if runner.missed_action and runner.missed_action.missed:
        console.print(
            Panel(
                runner.missed_action.detail,
                title="MISSED_ACTION - flagged for review, nothing executed",
                border_style="yellow",
            )
        )

    if report.ai_summary:
        console.print(
            Panel(
                Text(report.ai_summary),  # plain text: no markup from a model
                title="AI-written summary - NOT evidence",
                border_style="dim",
            )
        )

    chain = runner.audit.verify_chain()
    console.print(
        Panel(
            f"status: [bold {colour}]{report.status.value}[/bold {colour}]\n"
            f"missing: {', '.join(report.missing) or 'nothing'}\n"
            f"policy hash: [dim]{report.policy_hash[:32]}...[/dim]\n"
            f"audit chain: {'intact' if chain.ok else 'BROKEN'} ({chain.entries} entries)",
            title=f"case {report.case_id}",
            border_style=colour,
        )
    )
    console.print(
        "[dim]Guarantees and non-guarantees: see README section "
        "'What this guarantees - and what it does not'.[/dim]"
    )


if __name__ == "__main__":
    app()
