"""A comparison between runs whose rules were graded by a different evaluator or judge.

A new judge model reading the same replies changes verdicts without the system
changing. Such a rule is refused by name, like a rule whose trials changed: no
finding of it reads as resolved or new, its cases are not paired, and the diff
cannot pass. Grading nobody recorded is unknown, never a change.
"""

from datetime import UTC, datetime

from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.diff import compare, compare_reports, gate_diff
from guardana.core.diff.model import ChangeKind, RunDiff
from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome
from guardana.core.manifest import RunManifest, TargetIdentity, ToolInfo
from guardana.core.manifest.records import EvaluatorRecord, ResultSummary
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings
from guardana.core.manifest.usage import RunUsage
from guardana.core.profile import Policy
from guardana.core.report import Evidence, Finding, RunReport, ScanResult
from guardana.core.severity import Severity
from guardana.core.target import TargetKind

_JUDGED = "acme.prompt.judged"
_ALSO_JUDGED = "acme.prompt.also_judged"
_KEYWORD = "acme.prompt.keyword"
_RULES = (_JUDGED, _ALSO_JUDGED, _KEYWORD)
_GRADER = {_JUDGED: "llm_judge", _ALSO_JUDGED: "llm_judge", _KEYWORD: "keyword"}
_ENDPOINT = "http://x#m"
_FIRST = datetime(2026, 8, 1, tzinfo=UTC)
_SECOND = datetime(2026, 8, 2, tzinfo=UTC)


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        taxonomy=(),
        target_ref=_ENDPOINT,
        evidence=Evidence(summary="complied"),
        verdict=Verdict("fail", 0.9, "complied", _GRADER[rule_id]),
    )


def _graded(
    rule_id: str,
    *,
    passed: bool | None = True,
    assessor: str | None = None,
    status: AssessmentStatus = AssessmentStatus.MEASURED,
    reason: UnmeasuredReason | None = None,
) -> Assessment:
    return Assessment(
        case_id=f"{rule_id}#case",
        assessor=assessor or _GRADER[rule_id],
        subject_ref=_ENDPOINT,
        status=status,
        rule_id=rule_id,
        passed=passed,
        dataset="d",
        reason=reason,
    )


def _report(
    *findings: Finding,
    when: datetime,
    judge: str | None,
    assessments: tuple[Assessment, ...] | None = None,
    evaluators: tuple[EvaluatorRecord, ...] | None = None,
    migrated_from: int | None = None,
) -> RunReport:
    recorded = (
        evaluators
        if evaluators is not None
        else (EvaluatorRecord(id="keyword"), EvaluatorRecord(id="llm_judge", judge=judge))
    )
    return RunReport(
        manifest=RunManifest(
            run_id="r",
            created_at=when,
            started_at=when,
            completed_at=when,
            guardana=ToolInfo(version="0.35.0"),
            target=TargetIdentity(kind=TargetKind.ENDPOINT, ref=_ENDPOINT),
            configuration=ConfigurationRef(profile_name="default"),
            execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
            usage=RunUsage(),
            result_summary=ResultSummary(
                findings=len(findings),
                unverified=0,
                waived=0,
                errors=0,
                observations=0,
                rules_run=_RULES,
                rules_skipped=(),
                max_severity=None,
                gate=GateOutcome.PASS,
            ),
            evaluators=recorded,
            migrated_from=migrated_from,
        ),
        result=ScanResult(
            findings=findings,
            rules_run=_RULES,
            rules_skipped=(),
            assessments=(
                assessments
                if assessments is not None
                else tuple(
                    _graded(rule, passed=not any(f.rule_id == rule for f in findings))
                    for rule in _RULES
                )
            ),
        ),
    )


def _kinds(diff: RunDiff) -> list[tuple[str, ChangeKind]]:
    return [(c.rule_id, c.kind) for c in diff.changes]


def test_a_new_judge_excludes_only_the_rules_it_graded() -> None:
    before = _report(_finding(_JUDGED), when=_FIRST, judge="model=a")
    after = _report(_finding(_ALSO_JUDGED), _finding(_KEYWORD), when=_SECOND, judge="model=b")

    diff = compare_reports(before, after)

    assert _kinds(diff) == [(_KEYWORD, ChangeKind.APPEARED)]
    assert diff.incomplete == (
        f"2 rule(s) were graded differently ({_ALSO_JUDGED}, {_JUDGED}) — a different "
        f"evaluator or judge — so their findings and measurements are not compared",
    )
    assert gate_diff(diff, Policy())


def test_a_regraded_rule_is_not_resolved_when_nothing_else_moved() -> None:
    diff = compare_reports(
        _report(_finding(_JUDGED), when=_FIRST, judge="model=a"),
        _report(when=_SECOND, judge="model=b"),
    )

    assert diff.improvements == ()
    assert gate_diff(diff, Policy())


def test_a_migrated_run_with_no_judge_on_record_excludes_nothing() -> None:
    diff = compare_reports(
        _report(_finding(_JUDGED), when=_FIRST, judge=None, migrated_from=12),
        _report(when=_SECOND, judge="model=b"),
    )

    assert _kinds(diff) == [(_JUDGED, ChangeKind.RESOLVED)]
    assert diff.incomplete == ()


def test_deterministic_evaluators_on_both_sides_compare_as_before() -> None:
    diff = compare_reports(
        _report(when=_FIRST, judge=None),
        _report(_finding(_KEYWORD), when=_SECOND, judge=None),
    )

    assert _kinds(diff) == [(_KEYWORD, ChangeKind.APPEARED)]
    assert diff.incomplete == ()


def test_the_same_judge_on_both_sides_compares_as_before() -> None:
    diff = compare_reports(
        _report(when=_FIRST, judge="model=a"),
        _report(_finding(_JUDGED), when=_SECOND, judge="model=a"),
    )

    assert _kinds(diff) == [(_JUDGED, ChangeKind.APPEARED)]
    assert diff.incomplete == ()


def test_the_measurement_of_a_regraded_rule_is_not_paired() -> None:
    same = compare_reports(
        _report(when=_FIRST, judge="model=a"), _report(when=_SECOND, judge="model=a")
    )
    regraded = compare_reports(
        _report(when=_FIRST, judge="model=a"), _report(when=_SECOND, judge="model=b")
    )

    assert same.measurement.paired == len(_RULES)
    assert regraded.measurement.paired == 1


def test_a_judge_named_under_a_versioned_assessor_is_still_read() -> None:
    versioned = "llm_judge@2025.1"

    def _run(judge: str, *findings: Finding, when: datetime) -> RunReport:
        return _report(
            *findings,
            when=when,
            judge=judge,
            assessments=(_graded(_JUDGED, assessor=versioned), _graded(_KEYWORD)),
        )

    diff = compare_reports(
        _run("model=a", _finding(_JUDGED), when=_FIRST), _run("model=b", when=_SECOND)
    )

    assert _kinds(diff) == []
    assert diff.incomplete


def test_a_rule_graded_by_another_evaluator_is_excluded() -> None:
    def _run(assessor: str, *findings: Finding, when: datetime) -> RunReport:
        return _report(
            *findings,
            when=when,
            judge=None,
            evaluators=(),
            assessments=(_graded(_JUDGED, assessor=assessor), _graded(_KEYWORD)),
        )

    diff = compare_reports(
        _run("judge-a", when=_FIRST), _run("judge-b", _finding(_JUDGED), when=_SECOND)
    )

    assert _kinds(diff) == []
    assert any(_JUDGED in reason for reason in diff.incomplete)


def test_an_evaluator_one_run_also_reached_is_not_a_grading_change() -> None:
    """A scenario stopped early grades fewer steps; reaching more is the system, not the grader."""

    def _run(*extra: Assessment, findings: tuple[Finding, ...] = (), when: datetime) -> RunReport:
        return _report(
            *findings,
            when=when,
            judge="model=a",
            assessments=(_graded(_JUDGED, assessor="keyword"), *extra),
        )

    diff = compare_reports(
        _run(when=_FIRST),
        _run(_graded(_JUDGED, assessor="llm_judge"), findings=(_finding(_JUDGED),), when=_SECOND),
    )

    assert _kinds(diff) == [(_JUDGED, ChangeKind.APPEARED)]
    assert diff.incomplete == ()


def test_a_trial_nobody_graded_names_no_grader() -> None:
    unrecorded = _graded(
        _JUDGED,
        assessor="recording",
        passed=None,
        status=AssessmentStatus.ERROR,
        reason=UnmeasuredReason.NOT_RECORDED,
    )
    diff = compare_reports(
        _report(when=_FIRST, judge="model=a"),
        _report(
            _finding(_JUDGED),
            when=_SECOND,
            judge="model=a",
            assessments=(unrecorded, _graded(_KEYWORD)),
        ),
    )

    assert _kinds(diff) == [(_JUDGED, ChangeKind.APPEARED)]
    assert diff.incomplete == ()


def test_a_comparison_without_saved_runs_knows_no_grading() -> None:
    before = _report(_finding(_JUDGED), when=_FIRST, judge="model=a")
    after = _report(when=_SECOND, judge="model=b")

    diff = compare(before.result, after.result)

    assert _kinds(diff) == [(_JUDGED, ChangeKind.RESOLVED)]
    assert diff.incomplete == ()
