"""A run that recorded errors must not compare as a whole run.

An error is a check that never ran — a refused pack, a rule that raised, a file
nobody could read — and its findings are missing from the run the same way a
stopped run's are. Subtracting two finding lists cannot tell that from a fix.
"""

from guardana.core.diff import compare
from guardana.core.diff.gate import gate_diff
from guardana.core.profile import Policy
from guardana.core.report import CheckError, Evidence, Finding, ScanResult
from guardana.core.severity import Severity

_RULES = ("guardana.a", "guardana.b")
_REFUSED_PACK = CheckError(
    source="acme-pack", stage="discovery", reason="PluginRefused: not admitted"
)


def _finding() -> Finding:
    return Finding("guardana.a", Severity.HIGH, "a problem", (), "", Evidence(summary="found"))


def _clean() -> ScanResult:
    return ScanResult(findings=(), rules_run=_RULES, rules_skipped=())


def _with_a_finding() -> ScanResult:
    return ScanResult(findings=(_finding(),), rules_run=_RULES, rules_skipped=())


def _errored() -> ScanResult:
    """The same rules and the same clean finding list, and a check that never ran."""
    return ScanResult(findings=(), rules_run=_RULES, rules_skipped=(), errors=(_REFUSED_PACK,))


def test_an_error_in_the_second_run_makes_the_comparison_incomplete() -> None:
    diff = compare(_clean(), _errored())

    assert diff.changes == (), "the finding lists really are identical — that is the trap"
    assert any("second run" in r and "acme-pack" in r for r in diff.incomplete), diff.incomplete


def test_an_error_in_the_first_run_counts_too() -> None:
    """A baseline with a check that never ran is not a baseline the second run improved on."""
    diff = compare(_errored(), _clean())

    assert any("first run" in r and "acme-pack" in r for r in diff.incomplete), diff.incomplete


def test_a_fix_over_an_errored_run_does_not_pass_the_gate() -> None:
    """The finding vanished, and so did a check: no policy waves that through."""
    diff = compare(_with_a_finding(), _errored())

    assert diff.incomplete
    assert gate_diff(diff, Policy()) is True


def test_two_runs_without_errors_still_compare_cleanly() -> None:
    diff = compare(_clean(), _clean())

    assert diff.incomplete == ()
    assert gate_diff(diff, Policy()) is False
