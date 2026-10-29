"""`acme-table` writes every channel of a run, in order, with the verdict on every row.

Runs are built in code, so each test states exactly what the run recorded.
"""

import csv
import dataclasses
import io
from typing import Any

import pytest
from acme_outputs import table
from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.gate import gate_outcome
from guardana.core.manifest.records import SuiteOutcome, SuiteSummary
from guardana.core.profile import Policy
from guardana.core.report import (
    CheckError,
    CoverageShortfall,
    Evidence,
    Finding,
    ScanResult,
    ShortfallKind,
    SkippedRule,
    SkipReason,
    StopReason,
)
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.testing import manifest_for
from guardana.core.testing.manifests import suite_summary
from guardana.core.verify import Verification

_RUN_ID = "00000000-0000-4000-8000-000000000000"
_SUITE = "acme.quality.answers"


def _finding(rule_id: str, severity: Severity = Severity.HIGH, summary: str = "seen") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=f"{rule_id} fired",
        taxonomy=(),
        target_ref="app.py:3",
        evidence=Evidence(summary=summary),
    )


def _case(**changes: Any) -> Assessment:  # noqa: ANN401 — any field of the assessment
    base = Assessment(
        case_id="case-1", assessor="contains", subject_ref="endpoint", rule_id=_SUITE, passed=True
    )
    return dataclasses.replace(base, **changes)


def _declined() -> SuiteSummary:
    return suite_summary(
        cases=3,
        measured=3,
        worst=0.5,
        best=0.5,
        low=0.1,
        high=0.9,
        min_sample=30,
        outcome=SuiteOutcome.INCONCLUSIVE,
        reason="3 cases measured, 30 needed",
    )


def _verification(result: ScanResult) -> Verification:
    gate = gate_outcome(result, Policy())
    manifest = manifest_for(
        result, gate=gate, target_ref="http://app.test/v1", target_kind=TargetKind.ENDPOINT
    )
    return Verification(result=result, manifest=manifest, gate=gate)


def _rows(result: ScanResult) -> list[dict[str, str]]:
    text = table.render(_verification(result))
    return list(csv.DictReader(io.StringIO(text, newline="")))


def _outcomes(rows: list[dict[str, str]]) -> list[str]:
    return [row["outcome"] for row in rows]


def _every_channel() -> ScanResult:
    return ScanResult(
        findings=(_finding("acme.found", Severity.MEDIUM),),
        rules_run=("acme.found", "acme.quiet", _SUITE),
        rules_skipped=(
            SkippedRule(
                "acme.skipped", SkipReason.MISSING_CAPABILITY, ("tools", "chat"), "no tools"
            ),
        ),
        unverified=(_finding("acme.unsure", Severity.LOW),),
        waived=(_finding("acme.accepted", Severity.CRITICAL),),
        errors=(CheckError(source="acme.broken", stage="run", reason="it raised"),),
        coverage_shortfall=(
            CoverageShortfall(ShortfallKind.MISSING_DIMENSION, "tools", "no tool calls recorded"),
        ),
        assessments=(_case(),),
        suites={_SUITE: _declined()},
    )


def test_the_text_is_rfc_4180_with_every_cell_quoted_and_crlf_endings() -> None:
    text = table.render(_verification(_every_channel()))

    lines = text.split("\r\n")
    assert lines[0] == ",".join(f'"{name}"' for name in table.HEADER)
    assert lines[-1] == ""
    assert "\n" not in text.replace("\r\n", "")
    assert all(line.startswith('"') and line.endswith('"') for line in lines[:-1])


def test_rows_follow_the_table_order_with_the_verdict_on_every_row() -> None:
    rows = _rows(_every_channel())

    assert _outcomes(rows) == [
        "run",
        "finding",
        "unverified",
        "waived",
        "error",
        "skipped",
        "shortfall",
        "case",
        "suite",
        "ran_no_finding",
    ]
    assert {row["run_id"] for row in rows} == {_RUN_ID}
    assert {row["gate"] for row in rows} == {"indeterminate"}


def test_the_run_row_carries_the_worst_severity_the_exit_code_and_every_open_question() -> None:
    run = _rows(_every_channel())[0]

    assert run["severity"] == "MEDIUM"
    assert run["location"] == "http://app.test/v1"
    assert run["status"] == "exit 2"
    assert run["detail"] == "coverage_shortfall;suite_declined;errors;unverified;skipped"


def test_a_stopped_run_names_what_stopped_it_in_the_run_row() -> None:
    result = ScanResult(
        findings=(), rules_run=(), rules_skipped=(), stopped_by=StopReason.BUDGET_EXHAUSTED
    )

    run = _rows(result)[0]

    assert run["status"] == "exit 6"
    assert run["detail"].split(";")[0] == "stopped:budget_exhausted"


def test_each_channel_row_fills_its_own_columns() -> None:
    rows = {row["outcome"]: row for row in _rows(_every_channel())}

    assert rows["finding"] | {"run_id": "", "gate": ""} == {
        "run_id": "",
        "gate": "",
        "outcome": "finding",
        "check": "acme.found",
        "case": "",
        "severity": "MEDIUM",
        "location": "app.py:3",
        "title": "acme.found fired",
        "status": "",
        "detail": "seen",
    }
    assert (rows["error"]["check"], rows["error"]["status"], rows["error"]["detail"]) == (
        "acme.broken",
        "run",
        "it raised",
    )
    assert rows["skipped"]["status"] == "missing_capability"
    assert rows["skipped"]["detail"] == "no tools; missing: tools, chat"
    assert (rows["shortfall"]["check"], rows["shortfall"]["status"]) == (
        "tools",
        "missing_dimension",
    )
    assert rows["suite"]["check"] == _SUITE
    assert rows["suite"]["status"] == "inconclusive"
    assert rows["suite"]["detail"] == "3 cases measured, 30 needed"
    assert rows["ran_no_finding"]["check"] == "acme.quiet"


@pytest.mark.parametrize(
    ("changes", "status", "detail"),
    [
        ({}, "passed", ""),
        ({"passed": False, "rationale": "no place named"}, "failed", "no place named"),
        (
            {"passed": None, "value": 0.25, "unit": "ratio", "threshold": 0.5},
            "measured",
            "value 0.25 ratio, threshold 0.5",
        ),
        (
            {
                "passed": None,
                "status": AssessmentStatus.INCONCLUSIVE,
                "reason": UnmeasuredReason.DECLINED,
                "rationale": "judge declined",
            },
            "inconclusive",
            "reason declined; judge declined",
        ),
        ({"passed": None, "status": AssessmentStatus.ERROR}, "error", ""),
        ({"passed": None, "status": AssessmentStatus.SKIPPED}, "skipped", ""),
    ],
)
def test_a_case_row_says_how_the_case_ended(
    changes: dict[str, Any], status: str, detail: str
) -> None:
    result = ScanResult(
        findings=(), rules_run=(_SUITE,), rules_skipped=(), assessments=(_case(**changes),)
    )

    (case,) = [row for row in _rows(result) if row["outcome"] == "case"]

    assert (case["status"], case["detail"]) == (status, detail)
    assert (case["check"], case["case"], case["location"]) == (_SUITE, "case-1", "endpoint")


def test_a_trial_is_appended_to_its_case() -> None:
    result = ScanResult(
        findings=(), rules_run=(_SUITE,), rules_skipped=(), assessments=(_case(trial=2),)
    )

    (case,) = [row for row in _rows(result) if row["outcome"] == "case"]

    assert case["case"] == "case-1#2"


def test_a_declined_suite_gets_no_ran_no_finding_row() -> None:
    result = ScanResult(
        findings=(), rules_run=(_SUITE,), rules_skipped=(), suites={_SUITE: _declined()}
    )

    rows = _rows(result)

    assert _outcomes(rows) == ["run", "suite"]
    assert rows[0]["detail"] == "suite_declined"


def test_a_stopped_run_gets_no_ran_no_finding_row_for_the_rule_it_cut_off() -> None:
    """The cut-off rule is not in `rules_run`; a rule that finished before the stop is."""
    result = ScanResult(
        findings=(),
        rules_run=("acme.finished",),
        rules_skipped=(),
        assessments=(_case(passed=None, status=AssessmentStatus.ERROR),),
        suites={_SUITE: _declined()},
        stopped_by=StopReason.BUDGET_EXHAUSTED,
    )

    rows = _rows(result)

    assert [r["check"] for r in rows if r["outcome"] == "ran_no_finding"] == ["acme.finished"]
    assert _SUITE in {r["check"] for r in rows if r["outcome"] in {"case", "suite"}}


def test_a_rule_that_ran_and_found_nothing_is_listed() -> None:
    result = ScanResult(findings=(), rules_run=("acme.quiet",), rules_skipped=())

    rows = _rows(result)

    assert [(r["outcome"], r["check"]) for r in rows[1:]] == [("ran_no_finding", "acme.quiet")]
    assert rows[0]["gate"] == "pass"


@pytest.mark.parametrize(
    "text",
    [
        "=1+1",
        "+1",
        "-1",
        "@SUM(A1)",
        ';=HYPERLINK("http://x.invalid")',
        ", =x",
        " =x",
        "\uff1dx",
        "\uff0bx",
        "\uff0dx",
        "\uff20x",
        "\tplain",
        "\rplain",
    ],
)
def test_a_cell_a_spreadsheet_would_evaluate_is_neutralised(text: str) -> None:
    result = ScanResult(
        findings=(_finding("acme.found", summary=text),), rules_run=(), rules_skipped=()
    )

    (finding,) = [row for row in _rows(result) if row["outcome"] == "finding"]

    assert finding["detail"] == f"'{text}"


@pytest.mark.parametrize("text", ["plain", "a=b", "value -1", "a;=b", ""])
def test_an_ordinary_cell_is_written_as_it_is(text: str) -> None:
    result = ScanResult(
        findings=(_finding("acme.found", summary=text),), rules_run=(), rules_skipped=()
    )

    (finding,) = [row for row in _rows(result) if row["outcome"] == "finding"]

    assert finding["detail"] == text


# What the table writes from each type, and what it leaves out by name. A field in
# neither set is a field added after this table was written, and silently dropped.
_EXPORTED = {
    ScanResult: {
        "findings",
        "rules_run",
        "rules_skipped",
        "unverified",
        "waived",
        "errors",
        "coverage_shortfall",
        "stopped_by",
        "assessments",
        "suites",
    },
    Assessment: {
        "case_id",
        "subject_ref",
        "status",
        "rule_id",
        "passed",
        "value",
        "unit",
        "threshold",
        "rationale",
        "trial",
        "reason",
    },
    SuiteSummary: {"outcome", "reason"},
}
_EXCLUDED = {
    ScanResult: {"observations", "usage", "protocols", "trials_per_case", "scope"},
    Assessment: {"assessor", "direction", "confidence", "dataset", "tags"},
    SuiteSummary: {
        "dataset",
        "dataset_digest",
        "trials_per_case",
        "cases",
        "measured",
        "ungraded",
        "min_pass_rate",
        "min_sample",
        "correction",
        "worst",
        "best",
        "low",
        "high",
        "sample_size",
        "sample_seed",
    },
}


@pytest.mark.parametrize("kind", [ScanResult, Assessment, SuiteSummary], ids=lambda k: k.__name__)
def test_every_field_is_exported_or_excluded_by_name(kind: type) -> None:
    names = {item.name for item in dataclasses.fields(kind)}

    assert names - _EXPORTED[kind] - _EXCLUDED[kind] == set()
    assert _EXPORTED[kind] & _EXCLUDED[kind] == set()
    assert (_EXPORTED[kind] | _EXCLUDED[kind]) - names == set()


_EMPTY = ScanResult(findings=(), rules_run=(), rules_skipped=())
_POPULATED: dict[str, Any] = {
    "findings": (_finding("acme.found"),),
    "rules_run": ("acme.quiet",),
    "rules_skipped": (SkippedRule("acme.skipped", SkipReason.NOT_APPLICABLE, (), "n/a"),),
    "unverified": (_finding("acme.unsure"),),
    "waived": (_finding("acme.accepted"),),
    "errors": (CheckError(source="acme.broken", stage="run", reason="it raised"),),
    "coverage_shortfall": (CoverageShortfall(ShortfallKind.DEMANDED_CHECK, "acme.x", "absent"),),
    "stopped_by": StopReason.INTERRUPTED,
    "assessments": (_case(),),
    "suites": {_SUITE: suite_summary()},
}
_CHANGED_CASE: dict[str, Any] = {
    "case_id": "case-2",
    "subject_ref": "elsewhere",
    "status": AssessmentStatus.SKIPPED,
    "rule_id": "acme.other",
    "passed": False,
    "value": 0.5,
    "unit": "ratio",
    "threshold": 0.5,
    "rationale": "why",
    "trial": 3,
    "reason": UnmeasuredReason.DECLINED,
}


@pytest.mark.parametrize("name", sorted(_EXPORTED[ScanResult]))
def test_every_exported_result_channel_changes_the_table(name: str) -> None:
    assert _rows(dataclasses.replace(_EMPTY, **{name: _POPULATED[name]})) != _rows(_EMPTY)


@pytest.mark.parametrize("name", sorted(_EXPORTED[Assessment]))
def test_every_exported_case_field_changes_the_table(name: str) -> None:
    base = _case(passed=None, value=0.25, status=AssessmentStatus.MEASURED)
    changes = {name: _CHANGED_CASE[name]}
    if name == "reason":
        changes["status"] = AssessmentStatus.INCONCLUSIVE
    changed = dataclasses.replace(base, **changes)
    before = ScanResult(findings=(), rules_run=(), rules_skipped=(), assessments=(base,))

    assert _rows(dataclasses.replace(before, assessments=(changed,))) != _rows(before)


@pytest.mark.parametrize("name", sorted(_EXPORTED[SuiteSummary]))
def test_every_exported_suite_field_changes_the_table(name: str) -> None:
    declined = _declined()
    before = ScanResult(findings=(), rules_run=(), rules_skipped=(), suites={_SUITE: declined})
    changed = (
        dataclasses.replace(declined, reason="another reason")
        if name == "reason"
        else suite_summary()
    )

    assert _rows(dataclasses.replace(before, suites={_SUITE: changed})) != _rows(before)
