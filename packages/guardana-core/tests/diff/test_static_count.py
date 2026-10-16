"""A new static finding in a file that already held one of the same rule is a regression."""

from guardana.core.diff import ChangeKind, compare
from guardana.core.diff.gate import gate_diff
from guardana.core.monitor import Alert, Monitor, MonitorConfig
from guardana.core.profile import FailOn, Policy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.target.scope import FileScope

_RULE = "guardana.supply_chain.code_execution"
_FILE = "src/run.py"


def _sink(line: int) -> Finding:
    return Finding(
        _RULE, Severity.HIGH, "sink", (), f"{_FILE}:{line}", Evidence(summary=f"sink {line}")
    )


def _run(
    findings: tuple[Finding, ...] = (),
    waived: tuple[Finding, ...] = (),
    *,
    files: tuple[str, ...] | None = (_FILE,),
) -> ScanResult:
    return ScanResult(
        findings=findings,
        rules_run=(_RULE,),
        rules_skipped=(),
        waived=waived,
        scope=None if files is None else FileScope(files=files),
    )


def test_a_second_sink_in_an_already_flagged_file_appeared_and_gates() -> None:
    diff = compare(_run((_sink(3),)), _run((_sink(3), _sink(9))))

    assert [c.kind for c in diff.changes] == [ChangeKind.APPEARED]
    assert "1 more HIGH finding(s)" in diff.changes[0].detail
    assert gate_diff(diff, Policy()) is True


def test_a_new_sink_beside_a_waived_one_appeared_rather_than_changed_waiver() -> None:
    diff = compare(_run(waived=(_sink(3),)), _run((_sink(9),), waived=(_sink(3),)))

    assert [c.kind for c in diff.changes] == [ChangeKind.APPEARED]
    assert gate_diff(diff, Policy()) is True


def test_a_new_sink_somebody_waived_is_a_count_that_does_not_gate() -> None:
    diff = compare(_run((_sink(3),)), _run((_sink(3),), waived=(_sink(9),)))

    assert [c.kind for c in diff.changes] == [ChangeKind.COUNT_CHANGED]
    assert gate_diff(diff, Policy()) is False


def test_a_waiver_removed_from_an_unchanged_sink_is_still_a_waiver_change() -> None:
    diff = compare(_run(waived=(_sink(3),)), _run((_sink(3),)))

    assert [c.kind for c in diff.changes] == [ChangeKind.WAIVER_CHANGED]


def test_one_sink_fewer_in_a_file_is_a_count_that_does_not_gate() -> None:
    diff = compare(_run((_sink(3), _sink(9))), _run((_sink(3),)))

    assert [c.kind for c in diff.changes] == [ChangeKind.COUNT_CHANGED]
    assert gate_diff(diff, Policy()) is False


def test_a_run_that_listed_no_files_keeps_a_rising_count_ungated() -> None:
    """Without a file listing on both sides the runs are not known to be file scans."""
    diff = compare(_run((_sink(3),), files=None), _run((_sink(3), _sink(9)), files=None))

    assert [c.kind for c in diff.changes] == [ChangeKind.COUNT_CHANGED]


def test_the_monitor_alerts_on_a_second_sink_in_a_flagged_file_below_its_gate() -> None:
    """The monitor reads `compare` too, so a file-scanning watch sees the new sink."""
    cycles = iter((_run((_sink(3),)), _run((_sink(3), _sink(9)))))
    alerts: list[Alert] = []
    lenient = Policy(fail_on=FailOn(severity=Severity.CRITICAL))

    Monitor(
        scan=lambda: next(cycles),
        policy=lenient,
        config=MonitorConfig(interval_seconds=0.0, max_cycles=2),
    ).run(alerts.append, sleep=lambda _s: None)

    assert [(a.cycle, a.reason) for a in alerts] == [(1, "worse than the first cycle: appeared")]


def _secret(line: int, which: str) -> Finding:
    return Finding(
        _RULE, Severity.HIGH, "secret", (), f"{_FILE}:{line}", Evidence(summary=f"key {which}")
    )


def test_a_new_finding_that_replaced_a_fixed_one_appeared_and_gates() -> None:
    before = _run((_secret(1, "first"), _secret(2, "second")))
    after = _run((_secret(1, "first"), _secret(2, "third")))

    diff = compare(before, after)

    assert [c.kind for c in diff.changes] == [ChangeKind.APPEARED]
    assert gate_diff(diff, Policy()) is True


def test_the_same_findings_on_other_lines_are_unchanged() -> None:
    before = _run((_secret(1, "first"), _secret(2, "second")))
    after = _run((_secret(11, "first"), _secret(12, "second")))

    diff = compare(before, after)

    assert diff.changes == ()
    assert diff.unchanged == 1


def test_a_replacement_somebody_waived_does_not_gate() -> None:
    before = _run((_secret(1, "first"),))
    after = _run(waived=(_secret(1, "third"),))

    diff = compare(before, after)

    assert ChangeKind.APPEARED not in [c.kind for c in diff.changes]


def test_a_second_secret_sharing_a_shown_prefix_with_one_already_there_appeared() -> None:
    before = _run((_secret(1, "AKIA…"), _secret(2, "ghp_…")))
    after = _run((_secret(1, "AKIA…"), _secret(2, "AKIA…")))

    diff = compare(before, after)

    assert [c.kind for c in diff.changes] == [ChangeKind.APPEARED]
