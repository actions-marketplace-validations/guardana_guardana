"""`acme-table`: one run as a CSV table, one row per thing the run recorded.

RFC 4180 with every cell quoted and CRLF line endings. `run_id` and `gate` repeat on
every row, so a filtered sheet still shows the verdict. A cell a spreadsheet would read
as a formula is prefixed with `'`.
"""

import csv
import io
from collections.abc import Iterator, Sequence

from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.gate import OpenQuestion
from guardana.core.output import RendererSpec
from guardana.core.verify import Verification

NAME = "acme-table"

HEADER = (
    "run_id",
    "gate",
    "outcome",
    "check",
    "case",
    "severity",
    "location",
    "title",
    "status",
    "detail",
)

_FORMULA_STARTS = frozenset("=+-@\uff1d\uff0b\uff0d\uff20")
_SEPARATORS = ",;"

Row = tuple[str, str, str, str, str, str, str, str]
"""One row from `outcome` to `detail`; `run_id` and `gate` are added when written."""


def spec() -> RendererSpec:
    """Return the `acme-table` format."""
    return RendererSpec(
        name=NAME,
        summary="the run as one CSV table: the verdict, every finding, case and gap",
        render=render,
    )


def render(verification: Verification) -> str:
    """Write `verification` as CSV text: a header, then one row per recorded fact."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(HEADER)
    lead = (verification.manifest.run_id, str(verification.gate))
    for row in rows(verification):
        writer.writerow([neutralise(cell) for cell in (*lead, *row)])
    return buffer.getvalue()


def neutralise(cell: str) -> str:
    """Prefix `'` to a cell a spreadsheet would evaluate as a formula.

    A cell is one when it starts with a tab or a carriage return, or when its first
    character past whitespace and field separators starts a formula, full-width forms
    included: a reader that splits on `;` or `,` would otherwise see the formula start a
    cell of its own.
    """
    if cell.startswith(("\t", "\r")):
        return f"'{cell}"
    stripped = cell.lstrip()
    while stripped and stripped[0] in _SEPARATORS:
        stripped = stripped[1:].lstrip()
    if stripped and stripped[0] in _FORMULA_STARTS:
        return f"'{cell}"
    return cell


def rows(verification: Verification) -> Iterator[Row]:
    """Yield every row after the header, in the table's order, each channel in result order."""
    result = verification.result
    worst = result.max_severity()
    questions = [
        f"stopped:{result.stopped_by}" if question is OpenQuestion.STOPPED else str(question)
        for question in verification.open_questions
    ]
    yield (
        "run",
        "",
        "",
        "" if worst is None else worst.name,
        verification.manifest.target.ref,
        "",
        f"exit {verification.exit_code}",
        ";".join(questions),
    )
    named: set[str] = set()
    for row in _channel_rows(verification):
        named.add(row[1])
        yield row
    for rule_id in result.rules_run:
        if rule_id not in named:
            yield ("ran_no_finding", rule_id, "", "", "", "", "", "")


def _channel_rows(verification: Verification) -> Iterator[Row]:
    result = verification.result
    for outcome, findings in (
        ("finding", result.findings),
        ("unverified", result.unverified),
        ("waived", result.waived),
    ):
        for finding in findings:
            yield (
                outcome,
                finding.rule_id,
                "",
                finding.severity.name,
                finding.target_ref,
                finding.title,
                "",
                finding.evidence.summary,
            )
    for error in result.errors:
        yield ("error", error.source, "", "", "", "", error.stage, error.reason)
    for skip in result.rules_skipped:
        missing = f"missing: {', '.join(skip.missing)}" if skip.missing else ""
        yield (
            "skipped",
            skip.rule_id,
            "",
            "",
            "",
            "",
            str(skip.reason),
            _joined(skip.detail, missing),
        )
    for shortfall in result.coverage_shortfall:
        yield ("shortfall", shortfall.name, "", "", "", "", str(shortfall.kind), shortfall.detail)
    for assessment in result.assessments:
        yield _case_row(assessment)
    for rule_id, summary in result.suites.items():
        yield ("suite", rule_id, "", "", "", "", str(summary.outcome), summary.reason or "")


def _case_row(assessment: Assessment) -> Row:
    case = assessment.case_id
    if assessment.trial is not None:
        case = f"{case}#{assessment.trial}"
    return (
        "case",
        assessment.rule_id,
        case,
        "",
        assessment.subject_ref,
        "",
        case_status(assessment),
        case_detail(assessment),
    )


def case_status(assessment: Assessment) -> str:
    """Say how a case ended: `passed`, `failed`, `measured` without a verdict, or its status."""
    if assessment.status is not AssessmentStatus.MEASURED:
        return str(assessment.status)
    if assessment.passed is None:
        return "measured"
    return "passed" if assessment.passed else "failed"


def case_detail(assessment: Assessment) -> str:
    """Join the measured value and threshold, the unmeasured reason and the rationale."""
    measured = ""
    if assessment.value is not None:
        measured = f"value {assessment.value:g}"
        if assessment.unit:
            measured += f" {assessment.unit}"
        if assessment.threshold is not None:
            measured += f", threshold {assessment.threshold:g}"
    reason = "" if assessment.reason is None else f"reason {assessment.reason}"
    return _joined(measured, reason, assessment.rationale)


def _joined(*parts: str) -> str:
    present: Sequence[str] = [part for part in parts if part]
    return "; ".join(present)
