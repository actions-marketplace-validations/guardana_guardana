"""A cycle its target stopped sampled nothing: it warns, and is never the baseline.

A failure it proved before the stop still alerts and still fails the watch. The first cycle
that stops ends the watch with its cause, as a target that never answered does; a cycle the
budget stopped is still a sampled cycle with its own result code.
"""

from collections.abc import Callable, Iterator

import pytest
from guardana.core.evaluator import Verdict
from guardana.core.monitor import Alert, Monitor, MonitorConfig, TargetStoppedError
from guardana.core.profile import Policy
from guardana.core.report import CheckError, Evidence, Finding, ScanResult, StopReason
from guardana.core.severity import Severity

_REASON = "endpoint http://fake#m returned HTTP 503; its body begins: down"
_CLEAN = ScanResult((), rules_run=("r0",), rules_skipped=())
_HIT = Finding(
    rule_id="guardana.ep.hit",
    severity=Severity.HIGH,
    title="hit",
    taxonomy=(),
    target_ref="http://fake#m",
    evidence=Evidence(summary="x"),
    verdict=Verdict(outcome="fail", confidence=0.9, rationale="r", evaluator_id="e"),
)


def _stopped(
    by: StopReason = StopReason.TARGET_UNAVAILABLE, findings: tuple[Finding, ...] = (_HIT,)
) -> ScanResult:
    return ScanResult(
        findings,
        rules_run=(),
        rules_skipped=(),
        errors=(CheckError(source="r0", stage="target", reason=_REASON),),
        stopped_by=by,
    )


def _scans(*results: ScanResult) -> Callable[[], ScanResult]:
    cycles: Iterator[ScanResult] = iter(results)
    return lambda: next(cycles)


def _monitor(scan: Callable[[], ScanResult], cycles: int) -> Monitor:
    return Monitor(
        scan=scan, policy=Policy(), config=MonitorConfig(interval_seconds=0, max_cycles=cycles)
    )


def test_a_cycle_its_target_stopped_warns_and_is_not_sampled() -> None:
    alerts: list[Alert] = []
    warned: list[tuple[int, Exception]] = []

    summary = _monitor(_scans(_CLEAN, _stopped(findings=()), _CLEAN), 3).run(
        alerts.append,
        on_error=lambda cycle, exc: warned.append((cycle, exc)),
        sleep=lambda _s: None,
    )

    assert [(cycle, str(exc)) for cycle, exc in warned] == [(1, _REASON)]
    assert alerts == []
    assert (summary.cycles, summary.unsampled, summary.exit_code) == (2, 1, 0)


def test_a_failure_a_stopped_cycle_proved_alerts_and_fails_the_watch() -> None:
    alerts: list[Alert] = []
    warned: list[tuple[int, Exception]] = []

    summary = _monitor(_scans(_CLEAN, _stopped(), _CLEAN), 3).run(
        alerts.append,
        on_error=lambda cycle, exc: warned.append((cycle, exc)),
        sleep=lambda _s: None,
    )

    assert [cycle for cycle, _exc in warned] == [1]
    assert [(a.cycle, a.result.findings) for a in alerts] == [(1, (_HIT,))]
    assert (summary.cycles, summary.alerts, summary.unsampled) == (2, 1, 1)
    assert summary.exit_code == 1


def test_a_finding_below_the_bar_in_a_stopped_cycle_does_not_alert() -> None:
    alerts: list[Alert] = []
    low = Finding(
        rule_id="guardana.ep.low",
        severity=Severity.LOW,
        title="low",
        taxonomy=(),
        target_ref="http://fake#m",
        evidence=Evidence(summary="x"),
    )

    summary = _monitor(_scans(_CLEAN, _stopped(findings=(low,))), 2).run(
        alerts.append, sleep=lambda _s: None
    )

    assert alerts == []
    assert (summary.unsampled, summary.exit_code) == (1, 0)


def test_a_stopped_cycle_is_never_the_baseline() -> None:
    alerts: list[Alert] = []

    with pytest.raises(TargetStoppedError, match="returned HTTP 503") as stopped:
        _monitor(_scans(_stopped(findings=()), _CLEAN), 2).run(alerts.append, sleep=lambda _s: None)

    assert stopped.value.result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert alerts == []


def test_a_first_cycle_that_stopped_alerts_its_failure_before_ending_the_watch() -> None:
    alerts: list[Alert] = []

    with pytest.raises(TargetStoppedError, match="returned HTTP 503"):
        _monitor(_scans(_stopped(), _CLEAN), 2).run(alerts.append, sleep=lambda _s: None)

    assert [(a.cycle, a.result.findings) for a in alerts] == [(0, (_HIT,))]


def test_a_cycle_the_budget_stopped_is_still_sampled() -> None:
    summary = _monitor(_scans(_CLEAN, _stopped(StopReason.BUDGET_EXHAUSTED)), 2).run(
        lambda _a: None, sleep=lambda _s: None
    )

    assert (summary.cycles, summary.unsampled) == (2, 0)
    assert summary.exit_code == 6


def test_a_cycle_its_target_changed_under_warns_and_is_not_sampled() -> None:
    warned: list[tuple[int, Exception]] = []

    summary = _monitor(
        _scans(_CLEAN, _stopped(StopReason.TARGET_CHANGED, findings=()), _CLEAN), 3
    ).run(
        lambda _a: None,
        on_error=lambda cycle, exc: warned.append((cycle, exc)),
        sleep=lambda _s: None,
    )

    assert [(cycle, str(exc)) for cycle, exc in warned] == [(1, _REASON)]
    assert (summary.cycles, summary.unsampled, summary.exit_code) == (2, 1, 0)
