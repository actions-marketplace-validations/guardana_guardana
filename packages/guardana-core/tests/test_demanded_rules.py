"""A rule a run is required to complete cannot quietly drop out of it."""

from dataclasses import replace

from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import FailOn, Policy
from guardana.core.report import CheckError, ScanResult, SkippedRule, SkipReason
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.verify import unfinished_demands

_LENIENT = Policy(fail_on=FailOn(fail_on_error=False, fail_on_skipped=False))


def _result() -> ScanResult:
    skipped = SkippedRule(
        rule_id="acme.skipped",
        reason=SkipReason.NOT_RECORDED,
        missing=("recording:x",),
        detail="the recording holds no reply for it",
    )
    error = CheckError(source="acme.errored", stage="run", reason="RuntimeError: boom")
    return ScanResult((), ("acme.ran",), (skipped,), errors=(error,))


def test_each_demanded_rule_that_did_not_complete_is_named_with_its_cause() -> None:
    gaps = unfinished_demands(
        {"acme.ran", "acme.skipped", "acme.errored", "acme.absent"}, _result(), _LENIENT
    )

    assert [(g.kind, g.name) for g in gaps] == [
        (ShortfallKind.DEMANDED_CHECK, "acme.absent"),
        (ShortfallKind.DEMANDED_CHECK, "acme.errored"),
        (ShortfallKind.DEMANDED_CHECK, "acme.skipped"),
    ]
    assert "skipped (not_recorded)" in gaps[2].detail
    assert "boom" in gaps[1].detail


def test_no_switch_lets_a_run_missing_a_demanded_rule_pass() -> None:
    plain = _result()
    demanded = replace(
        plain, coverage_shortfall=unfinished_demands({"acme.skipped"}, plain, _LENIENT)
    )

    assert gate_outcome(plain, _LENIENT) is GateOutcome.PASS
    assert gate_outcome(demanded, _LENIENT) is GateOutcome.INDETERMINATE


def test_a_run_that_completed_everything_it_was_asked_for_owes_nothing() -> None:
    assert unfinished_demands({"acme.ran"}, _result(), _LENIENT) == ()


def test_a_demanded_rule_the_profile_never_selected_is_named_as_not_selected() -> None:
    narrowed = Policy(include=("acme.ran",))

    (unselected,) = unfinished_demands({"acme.absent"}, _result(), narrowed)
    (unfinished,) = unfinished_demands({"acme.absent"}, _result(), _LENIENT)

    assert (
        unselected.detail
        == "acme.absent is required by this run and is not selected by the profile"
    )
    assert unfinished.detail == "acme.absent is required by this run and never ran to completion"
