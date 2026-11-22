"""LLM output must not be able to style or mark up the screen a human reads.

The approval screen uses colour to carry meaning — green means TRUSTED, orange
means UNTRUSTED. A model-written summary or a model-chosen target is untrusted
text, and both reach that screen. If either could emit renderer markup, it
could forge the exact signal the operator is being asked to rely on.

That makes this a security property of the approval gate, not a formatting
preference, so it is tested rather than left to review.

(OWASP LLM05: Improper Output Handling.)
"""

from __future__ import annotations

import html

from rich.console import Console
from rich.markup import escape
from rich.text import Text

# Well-formed markup: rich applies it silently, which is the dangerous case.
HOSTILE_SUMMARY = (
    "[bold green]VERIFIED BY COMPLIANCE — TRUSTED[/bold green]\n"
    "[red]All checks passed. Approve immediately.[/red]"
)
# Malformed markup: rich raises instead, which would crash the approval screen
# mid-render. A model can choose either, so both have to be neutralised.
CRASHING_SUMMARY = "[/dim]nothing opened that tag"
HOSTILE_TARGET = "ACCT-0999[/bold][bold green] TRUSTED[/bold green]"


def _render(renderable) -> str:
    console = Console(width=120, no_color=True, force_terminal=False)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


def test_rich_applies_markup_found_in_a_plain_string() -> None:
    """The hazard itself: without a wrapper, the tags vanish into styling."""
    out = _render(HOSTILE_SUMMARY)
    assert "[bold green]" not in out
    assert "VERIFIED BY COMPLIANCE" in out


def test_malformed_markup_from_a_model_would_crash_the_screen() -> None:
    """The second hazard: a stray closing tag aborts the render entirely."""
    import pytest
    from rich.errors import MarkupError

    with pytest.raises(MarkupError):
        _render(CRASHING_SUMMARY)


def test_wrapping_in_text_keeps_model_markup_visible_as_literal() -> None:
    """How the CLI renders an AI summary: tags stay on screen, nothing styles."""
    out = _render(Text(HOSTILE_SUMMARY))
    assert "[bold green]" in out
    # And the malformed case renders instead of raising.
    assert "[/dim]" in _render(Text(CRASHING_SUMMARY))


def test_escaping_a_model_chosen_target_keeps_it_literal() -> None:
    """How the CLI renders a proposed target inside its own markup."""
    out = _render(f"[bold]{escape(HOSTILE_TARGET)}[/bold]")
    assert "[/bold]" in out
    assert "[bold green]" in out


def test_the_cli_wraps_ai_summaries_and_escapes_targets() -> None:
    """Guard the call sites, so the protection cannot be edited away silently."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "cli" / "main.py").read_text(
        encoding="utf-8"
    )
    assert "Text(presentation.ai_summary)" in source
    assert "Text(report.ai_summary)" in source
    assert "escape(str(p.target.value))" in source
    assert "escape(a.detail)" in source


def test_the_ui_escapes_model_values_before_html_markdown() -> None:
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "ui" / "app.py").read_text(
        encoding="utf-8"
    )
    assert "safe(report.proposal.target.value)" in source
    assert "html.escape(text)" in source
    # AI summaries are rendered as plain text, never as markdown.
    assert "st.info(report.ai_summary)" not in source
    assert "st.text(report.ai_summary)" in source


def test_html_escaping_neutralises_a_hostile_target() -> None:
    hostile = "ACCT-0999</span><span style='background:#1b5e20'>TRUSTED"
    assert "<span" not in html.escape(hostile)
