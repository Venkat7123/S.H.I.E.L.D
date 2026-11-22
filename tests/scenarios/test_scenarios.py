"""Every demo scenario, as a test.

``shield attack all`` prints these; CI asserts them. The two must not drift,
so the test runs the same ``run_scenario`` the CLI does rather than
re-implementing the checks.
"""

from __future__ import annotations

import pytest

from data.seed import seed
from harness.scenarios import ORDER, SCENARIOS, run_scenario


@pytest.fixture
def scenario_db(tmp_path):
    path = tmp_path / "scenarios.db"
    seed(path)
    return str(path)


@pytest.mark.scenario
@pytest.mark.parametrize("scenario_id", ORDER)
def test_scenario(scenario_id: str, scenario_db: str, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("harness.scenarios.JSONL", str(tmp_path / "audit.jsonl"))
    result = run_scenario(scenario_id, scenario_db)
    assert result.passed, (
        f"{result.id} ({result.title})\n"
        f"  expected: {result.expected}\n"
        f"  actual  : {result.actual}\n"
        f"  detail  : {result.detail}"
    )


@pytest.mark.scenario
def test_every_scenario_in_the_prd_is_present() -> None:
    """The PRD names twelve. If one is dropped, say so loudly."""
    assert set(ORDER) == set(SCENARIOS)
    assert len(ORDER) == 12


@pytest.mark.scenario
@pytest.mark.parametrize(
    "case_id,expected_status,expected_stop",
    [
        ("CASE-001", "COMPLETE", "COMPLETED"),          # genuine fraud -> freeze
        ("CASE-002", "COMPLETE", "THRESHOLD_NOT_MET"),  # poisoned memo -> refused
        ("CASE-003", "ESCALATED", "ESCALATED"),         # disagreement -> human
    ],
)
def test_plain_run_exercises_what_each_case_was_seeded_for(
    case_id, expected_status, expected_stop, tmp_path
) -> None:
    """``shield run --case X`` must not make every case look like CASE-001.

    The three fixtures were built to produce three different outcomes. If the
    generic runner put the cooperative script on all of them, CASE-002 and
    CASE-003 would silently behave like CASE-001 and the demo would show
    nothing.
    """
    from core.approval import ApprovalPresentation
    from data.seed import seed as seed_db
    from harness.runner import CaseRunner, RunOptions

    db = tmp_path / "run.db"
    seed_db(db)
    runner = CaseRunner(RunOptions(db_path=str(db), jsonl_path=str(tmp_path / "a.jsonl")))
    try:
        report = runner.run(case_id, decider=lambda _p: ("APPROVED", "test"))
        assert report.status.value == expected_status
        assert report.action is not None
        assert report.action.stop_reason.value == expected_stop
    finally:
        runner.close()


@pytest.mark.scenario
def test_results_are_identical_on_a_second_run(scenario_db, monkeypatch, tmp_path) -> None:
    """Stub mode must be reproducible, or the demo table means nothing."""
    monkeypatch.setattr("harness.scenarios.JSONL", str(tmp_path / "audit.jsonl"))
    first = run_scenario("B", scenario_db)
    second = run_scenario("B", scenario_db)
    assert first.passed and second.passed
    assert first.actual == second.actual
