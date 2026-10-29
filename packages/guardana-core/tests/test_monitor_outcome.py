"""A bounded watch ends with the worst outcome any of its cycles earned, never with silence.

Each cycle is judged as `probe` judges a run and as `guardana diff` judges the
comparison with the first cycle; the watch reports the worst of those, so an alert a
pipeline would act on is never followed by a clean exit.
"""

from typing import TYPE_CHECKING

from guardana.core.evaluator import Verdict
from guardana.core.gate import StopReason
from guardana.core.monitor import Monitor, MonitorConfig, MonitorSummary
from guardana.core.profile import FailOn, Policy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.target import EndpointError

if TYPE_CHECKING:
    from collections.abc import Iterator

_RULES = ("guardana.ep.watched", "guardana.ep.steady")


def _finding(severity: Severity, outcome: str = "fail") -> Finding:
    return Finding(
        rule_id="guardana.ep.watched",
        severity=severity,
        title="hit",
        taxonomy=(),
        target_ref="http://fake#m",
        evidence=Evidence(summary="x"),
        verdict=Verdict(outcome=outcome, confidence=0.9, rationale="r", evaluator_id="e"),  # type: ignore[arg-type]
    )


def _clean(rules: tuple[str, ...] = _RULES) -> ScanResult:
    return ScanResult((), rules_run=rules, rules_skipped=())


def _failing(severity: Severity = Severity.HIGH) -> ScanResult:
    return ScanResult((_finding(severity),), rules_run=_RULES, rules_skipped=())


def _watch(
    *cycles: ScanResult | Exception, policy: Policy | None = None, max_cycles: int | None = None
) -> MonitorSummary:
    items: Iterator[ScanResult | Exception] = iter(cycles)

    def scan() -> ScanResult:
        item = next(items)
        if isinstance(item, Exception):
            raise item
        return item

    return Monitor(
        scan=scan,
        policy=policy if policy is not None else Policy(),
        config=MonitorConfig(
            interval_seconds=0.0, max_cycles=len(cycles) if max_cycles is None else max_cycles
        ),
    ).run(lambda _alert: None, on_error=lambda _cycle, _exc: None, sleep=lambda _s: None)


def test_a_watch_whose_every_cycle_passed_reports_a_pass() -> None:
    summary = _watch(_clean(), _clean())

    assert summary.exit_code == 0
    assert (summary.cycles, summary.alerts, summary.unsampled) == (2, 0, 0)


def test_a_cycle_that_failed_the_gate_fails_the_watch() -> None:
    assert _watch(_failing()).exit_code == 1


def test_a_failed_cycle_is_not_forgotten_when_a_later_cycle_is_clean() -> None:
    summary = _watch(_failing(), _clean())

    assert summary.exit_code == 1
    assert summary.alerts == 1


def test_a_cycle_that_verified_nothing_makes_the_watch_indeterminate() -> None:
    assert _watch(_clean(rules=())).exit_code == 2


def test_a_cycle_the_budget_stopped_exits_as_a_stopped_run() -> None:
    stopped = ScanResult(
        (), rules_run=_RULES, rules_skipped=(), stopped_by=StopReason.BUDGET_EXHAUSTED
    )

    assert _watch(_clean(), stopped).exit_code == 6


def test_a_policy_failure_outranks_a_later_stop() -> None:
    stopped = ScanResult(
        (), rules_run=_RULES, rules_skipped=(), stopped_by=StopReason.BUDGET_EXHAUSTED
    )

    assert _watch(_failing(), stopped).exit_code == 1


def test_a_regression_the_diff_gate_refuses_fails_the_watch() -> None:
    lenient = Policy(fail_on=FailOn(severity=Severity.CRITICAL))
    blinded = ScanResult(
        (),
        rules_run=_RULES,
        rules_skipped=(),
        unverified=(_finding(Severity.HIGH, outcome="inconclusive"),),
    )

    assert _watch(_failing(), blinded, policy=lenient).exit_code == 1


def test_a_regression_below_the_bar_exits_as_guardana_diff_would() -> None:
    lenient = Policy(fail_on=FailOn(severity=Severity.CRITICAL))

    summary = _watch(_failing(Severity.LOW), _failing(Severity.HIGH), policy=lenient)

    assert summary.alerts == 1
    assert summary.exit_code == 0


def test_a_cycle_that_cannot_be_compared_with_the_first_is_indeterminate() -> None:
    lenient = Policy(fail_on=FailOn(severity=Severity.CRITICAL))

    summary = _watch(
        _clean(rules=("guardana.ep.watched",)), _clean(rules=("guardana.ep.other",)), policy=lenient
    )

    assert summary.exit_code == 2


def test_a_watch_that_sampled_no_cycle_is_indeterminate() -> None:
    assert _watch(max_cycles=0).exit_code == 2


def test_a_cycle_a_transient_failure_prevented_is_counted() -> None:
    summary = _watch(_clean(), EndpointError("reset"), _clean())

    assert (summary.cycles, summary.unsampled) == (2, 1)
    assert summary.exit_code == 0
