"""A run that could not get the coverage it demanded must not compare as unchanged.

Its finding list matches that of a run whose contract held, so what it did not reach
is unknown rather than absent, as for a stopped run.
"""

from guardana.core.diff import compare
from guardana.core.diff.gate import gate_diff
from guardana.core.profile import Policy
from guardana.core.report import CoverageShortfall, ScanResult, ShortfallKind

_RULES = ("guardana.a", "guardana.b")
_GAP = CoverageShortfall(
    kind=ShortfallKind.MISSING_DIMENSION,
    name="approval",
    detail="this producer records no approvals",
)


def _clean() -> ScanResult:
    return ScanResult(findings=(), rules_run=_RULES, rules_skipped=())


def _demanded_and_missing() -> ScanResult:
    """The same rules, the same clean finding list — and a demand that went unmet."""
    return ScanResult(findings=(), rules_run=_RULES, rules_skipped=(), coverage_shortfall=(_GAP,))


def test_a_run_with_unmet_coverage_makes_the_comparison_incomplete() -> None:
    diff = compare(_clean(), _demanded_and_missing())

    assert diff.changes == (), "the finding lists really are identical — that is the trap"
    assert any("approval" in reason for reason in diff.incomplete), diff.incomplete


def test_the_first_side_counts_too() -> None:
    """A baseline that could not answer is not a baseline the second run improved on."""
    diff = compare(_demanded_and_missing(), _clean())

    assert any("first run" in reason for reason in diff.incomplete), diff.incomplete


def test_no_policy_setting_waves_an_unmet_demand_through() -> None:
    """Before any threshold, like a stopped run: there is no verdict to weigh."""
    diff = compare(_clean(), _demanded_and_missing())

    assert gate_diff(diff, Policy()) is True


def test_coverage_nobody_demanded_is_named_as_missing_not_as_a_demand() -> None:
    empty = CoverageShortfall(
        kind=ShortfallKind.EMPTY_TARGET, name="packages", detail="no file left to scan"
    )
    after = ScanResult(findings=(), rules_run=_RULES, rules_skipped=(), coverage_shortfall=(empty,))

    (reason,) = compare(_clean(), after).incomplete

    assert "demanded" not in reason
    assert reason.startswith("the second run is missing coverage its verdict needs (packages)")


def test_two_complete_runs_still_compare_cleanly() -> None:
    """The guard must not make every comparison incomplete, which would be as useless."""
    diff = compare(_clean(), _clean())

    assert diff.incomplete == ()
    assert gate_diff(diff, Policy()) is False
