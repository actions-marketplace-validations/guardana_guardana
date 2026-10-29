"""A finding whose file the later run did not list left the scan; it was not resolved."""

from guardana.core.diff import ChangeKind, compare
from guardana.core.diff.gate import gate_diff
from guardana.core.evaluator.base import Verdict
from guardana.core.profile import FailOn, Policy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.target.scope import FileScope

_RULE = "guardana.supply_chain.pickle_opcode"


def _finding(path: str, *, unverified: bool = False) -> Finding:
    verdict = Verdict("inconclusive", 0.0, "could not parse", "x") if unverified else None
    return Finding(_RULE, Severity.LOW, "pickle", (), path, Evidence(summary="found"), verdict)


def _run(*, files: tuple[str, ...] | None, finding: Finding | None = None) -> ScanResult:
    unverified = finding is not None and finding.verdict is not None
    return ScanResult(
        findings=() if finding is None or unverified else (finding,),
        rules_run=(_RULE,),
        rules_skipped=(),
        unverified=(finding,) if finding is not None and unverified else (),
        scope=None if files is None else FileScope(files=files),
    )


def test_an_unverified_check_whose_file_left_is_not_clarified() -> None:
    before = _run(files=("m/a.pkl",), finding=_finding("m/a.pkl", unverified=True))

    diff = compare(before, _run(files=()))

    assert [c.kind for c in diff.changes] == [ChangeKind.LEFT_SCAN]


def test_left_scan_fails_the_gate_below_every_severity_bar() -> None:
    before = _run(files=("m/a.pkl",), finding=_finding("m/a.pkl"))
    strict = Policy(fail_on=FailOn(severity=Severity.CRITICAL, min_confidence=1.0))

    diff = compare(before, _run(files=()))

    assert gate_diff(diff, strict) is True


def test_a_second_run_that_recorded_no_listing_keeps_the_old_reading() -> None:
    """A migrated run or a caller that built no scope: nothing to tell a fix from a move."""
    before = _run(files=("m/a.pkl",), finding=_finding("m/a.pkl"))

    diff = compare(before, _run(files=None))

    assert [c.kind for c in diff.changes] == [ChangeKind.RESOLVED]


def test_a_listed_file_without_the_finding_is_resolved() -> None:
    before = _run(files=("m/a.pkl",), finding=_finding("m/a.pkl"))

    diff = compare(before, _run(files=("m/a.pkl",)))

    assert [c.kind for c in diff.changes] == [ChangeKind.RESOLVED]
    assert gate_diff(diff, Policy()) is False


def test_a_notebook_cell_whose_file_is_still_listed_is_resolved() -> None:
    """The notebook rule names `nb.ipynb:cell3`; the file part is what was listed."""
    before = _run(files=("m/nb.ipynb",), finding=_finding("m/nb.ipynb:cell3"))

    diff = compare(before, _run(files=("m/nb.ipynb",)))

    assert [c.kind for c in diff.changes] == [ChangeKind.RESOLVED]
