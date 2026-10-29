"""A run that was cut short must not print the tick people scroll for.

`StopReason` says why this exists in its own docstring: a report outlives the
process that wrote it, and one that does not say it was cut short reads as a
complete pass over the target. The exit code carries it — `6` for an exhausted
budget — but nobody reads an exit code off a terminal, and a job summary that says
"✓ No findings" over a run that stopped after two rules is the false green this
project exists against.

Found by running `probe --mcp --max-request 3` against a live server and reading
the output rather than the exit code.
"""

import json
from dataclasses import replace

import pytest
from guardana.core.assessment import Assessment
from guardana.core.gate import GateOutcome
from guardana.core.report import ScanResult, StopReason
from guardana.core.testing import manifest_for
from guardana.report import HumanRenderer, get_renderer

_STOPPED = ScanResult(
    findings=(),
    rules_run=("r0", "r1"),
    rules_skipped=(),
    stopped_by=StopReason.BUDGET_EXHAUSTED,
)
_COMPLETE = ScanResult(findings=(), rules_run=("r0", "r1"), rules_skipped=())


def test_a_stopped_run_never_prints_the_tick() -> None:
    text = HumanRenderer().render(_STOPPED)

    assert "✓" not in text
    assert "not an all-clear" in text


def test_the_reason_it_stopped_is_named() -> None:
    text = HumanRenderer().render(_STOPPED)

    assert "budget_exhausted" in text


def test_the_summary_line_says_the_run_was_cut_short() -> None:
    # The summary is the line CI job summaries quote, so it carries it too.
    assert "stopped early" in HumanRenderer().render(_STOPPED).splitlines()[-1]


def test_an_interrupted_run_is_treated_the_same_way() -> None:
    interrupted = ScanResult(
        findings=(), rules_run=("r0",), rules_skipped=(), stopped_by=StopReason.INTERRUPTED
    )

    assert "✓" not in HumanRenderer().render(interrupted)


def test_a_complete_run_with_nothing_to_report_still_gets_its_tick() -> None:
    text = HumanRenderer().render(_COMPLETE)

    assert "✓ No findings." in text
    assert "stopped early" not in text


def _reached(cases: int) -> tuple[Assessment, ...]:
    return tuple(
        Assessment(
            case_id=f"acme.prompt.demo#{c}",
            assessor="keyword",
            subject_ref="http://x#m",
            rule_id="acme.prompt.demo",
            passed=True,
            trial=1,
        )
        for c in range(cases)
    )


def test_a_stopped_run_says_its_case_count_ends_at_the_stop() -> None:
    # A rule the budget cut off after five of its ten prompts recorded five cases, so
    # a bare "5/5 case(s) measured" reads as every planned case measured.
    stopped = replace(_STOPPED, assessments=_reached(5))

    summary = HumanRenderer().render(stopped).splitlines()[-1]

    assert "5/5 case(s) measured before the run stopped." in summary


def test_a_complete_run_states_its_case_count_plainly() -> None:
    complete = replace(_COMPLETE, assessments=_reached(5))

    summary = HumanRenderer().render(complete).splitlines()[-1]

    assert "5/5 case(s) measured." in summary
    assert "before the run stopped" not in summary


def test_a_stopped_run_is_an_error_in_junit_not_a_clean_suite() -> None:
    # Dashboards read `errors="0" failures="0"` as a pass; the exit code alone is not
    # what a JUnit consumer sees.
    xml = get_renderer("junit").render(_STOPPED)

    assert 'errors="1"' in xml
    assert 'message="run stopped early"' in xml
    assert "budget_exhausted" in xml


def test_an_interrupted_run_is_an_error_in_junit_too() -> None:
    interrupted = replace(_STOPPED, stopped_by=StopReason.INTERRUPTED)

    assert 'message="run stopped early"' in get_renderer("junit").render(interrupted)


def test_a_complete_run_has_no_stop_error_in_junit() -> None:
    xml = get_renderer("junit").render(_COMPLETE)

    assert 'errors="0"' in xml
    assert "run stopped early" not in xml


_TARGET_STOPS = (StopReason.TARGET_UNAVAILABLE, StopReason.TARGET_CHANGED)


@pytest.mark.parametrize("stop", _TARGET_STOPS)
@pytest.mark.parametrize("name", ["human", "junit", "sarif", "json"])
def test_a_run_its_target_stopped_is_named_by_every_renderer(name: str, stop: StopReason) -> None:
    stopped = replace(_STOPPED, stopped_by=stop)
    manifest = manifest_for(stopped, gate=GateOutcome.INDETERMINATE)

    text = get_renderer(name, run=manifest).render(stopped)

    assert str(stop) in text
    assert "✓" not in text


@pytest.mark.parametrize("stop", _TARGET_STOPS)
def test_sarif_describes_the_exit_code_of_a_run_its_target_stopped(stop: StopReason) -> None:
    stopped = replace(_STOPPED, stopped_by=stop)
    manifest = manifest_for(stopped, gate=GateOutcome.INDETERMINATE)

    sarif = json.loads(get_renderer("sarif", run=manifest).render(stopped))

    [invocation] = sarif["runs"][0]["invocations"]
    assert invocation["exitCode"] == 4
    assert invocation["exitCodeDescription"] == (
        "target became unavailable or changed under the run, coverage partial"
    )
    assert invocation["executionSuccessful"] is False
