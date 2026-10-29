import re
from collections.abc import Callable
from xml.sax import saxutils

from guardana.core.gate import GateOutcome, OpenQuestion, declined_suites, open_questions
from guardana.core.manifest import RunManifest
from guardana.core.manifest.records import SuiteOutcome, SuiteSummary
from guardana.core.report import Finding, ScanResult, SkippedRule
from guardana.core.suite import describe
from guardana.report._refusal import (
    recorded_gate,
    refusal_clause,
    refused_skips,
    unnamed_refusal,
)
from guardana.report._subject import suite_name

_XML_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
"""Every character XML 1.0 forbids in a document, escaped or not."""


def _legal(value: str) -> str:
    """Replace what XML cannot carry with U+FFFD, so one byte cannot void the whole report."""
    return _XML_ILLEGAL.sub("\ufffd", value)


def _text(value: str) -> str:
    return saxutils.escape(_legal(value))


def _attr(value: str) -> str:
    return saxutils.quoteattr(_legal(value))


class JUnitRenderer:
    """JUnit XML — what most CI systems render as a test report."""

    name = "junit"

    def __init__(self, run: RunManifest | None = None, gate: GateOutcome | None = None) -> None:
        self._gate = recorded_gate(run, gate)
        self._suite = suite_name(run)

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        questions = open_questions(result)
        cases: list[str] = []
        # A suite is one testcase whatever it concluded, in place of its finding: a pass
        # rate is the suite's answer, and a pipeline counting testcases must see it pass.
        # A waived suite keeps its waived testcase instead.
        waived = {f.rule_id for f in result.waived}
        suites = {rule: s for rule, s in result.suites.items() if rule not in waived}
        findings = [f for f in result.findings if f.rule_id not in suites]
        unverified = [f for f in result.unverified if f.rule_id not in suites]
        declined = len(declined_suites(result))
        failed = sum(1 for s in suites.values() if s.outcome is SuiteOutcome.FAIL)
        cases.extend(
            _suite_case(rule_id, suite, _subject(result, rule_id))
            for rule_id, suite in sorted(suites.items())
        )
        for f in findings:
            name = _attr(f.rule_id)
            classname = _attr(f.target_ref)
            message = _attr(f.title)
            summary = _text(f.evidence.summary)
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <failure message={message}>{summary}</failure>\n"
                f"    </testcase>"
            )
        for f in unverified:
            name = _attr(f.rule_id)
            classname = _attr(f.target_ref)
            message = _attr(f.title)
            reason = _text(f.verdict.rationale if f.verdict is not None else f.evidence.summary)
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <skipped message={message}>{reason}</skipped>\n"
                f"    </testcase>"
            )
        for f in result.waived:
            name = _attr(f.rule_id)
            classname = _attr(f.target_ref)
            message = _attr(f.title)
            reason = _text(f"waived: {f.evidence.summary}")
            cases.append(
                f"    <testcase name={name} classname={classname}>\n"
                f"      <skipped message={message}>{reason}</skipped>\n"
                f"    </testcase>"
            )
        gaps = [skip for skip in result.rules_skipped if skip.is_coverage_gap]
        cases.extend(_skip_case(skip) for skip in gaps)
        # Every open question the renderers always name is one or more `<error>`
        # testcases, and so is a refusal the recorded gate made over nothing else named.
        errors = [case for q in questions for case in _OPEN_CASES[q](result, unverified)]
        refusal = unnamed_refusal(result, self._gate, questions)
        if refusal is not None:
            errors.append(_refusal_case(result, refusal))
        cases.extend(errors)
        body = "\n".join(cases)
        skipped = len(unverified) + len(result.waived) + len(gaps)
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name={_attr(self._suite)} tests="{result.rules_run_count + len(gaps)}" '
            f'failures="{len(findings) + failed}" skipped="{skipped}" '
            f'errors="{len(errors) + declined}">\n'
            f"{body}\n</testsuite>"
        )


def _error_case(name: str, classname: str, message: str, detail: str) -> str:
    return (
        f"    <testcase name={_attr(name)} classname={_attr(classname)}>\n"
        f"      <error message={_attr(message)}>{_text(detail)}</error>\n"
        f"    </testcase>"
    )


def _skip_case(skip: SkippedRule) -> str:
    """Write one testcase for a rule that never ran for want of coverage.

    Counted among the suite's tests, since a suite counting only the rules that ran reads
    as every check having happened.
    """
    missing = f"; missing: {', '.join(skip.missing)}" if skip.missing else ""
    classname = _attr(f"guardana.skipped.{skip.reason}")
    reason = _text(f"{skip.reason}{missing}")
    return (
        f"    <testcase name={_attr(skip.rule_id)} classname={classname}>\n"
        f"      <skipped message={_attr(skip.detail)}>{reason}</skipped>\n"
        f"    </testcase>"
    )


def _stopped_cases(result: ScanResult, _unverified: list[Finding]) -> list[str]:
    """Name a run cut short: `errors="0"` over one reads as a complete pass."""
    detail = (
        f"the run stopped early ({result.stopped_by}) before finishing its plan; "
        f"checks it never reached are not in this report"
    )
    return [_error_case("guardana.stopped", "guardana.run", "run stopped early", detail)]


def _nothing_verified_cases(result: ScanResult, _unverified: list[Finding]) -> list[str]:
    """One error for the run: a suite made only of `<skipped>` renders green everywhere."""
    detail = (
        f"{result.rules_run_count} check(s) ran and not one of them reached a "
        f"verdict, so this run established nothing"
    )
    return [_error_case("guardana.run", "guardana.coverage", "nothing was verified", detail)]


def _shortfall_cases(result: ScanResult, _unverified: list[Finding]) -> list[str]:
    """One error per piece of coverage the run did not get."""
    return [
        _error_case(
            gap.name,
            f"guardana.coverage.{gap.kind}",
            f"coverage missing ({gap.kind})",
            gap.detail,
        )
        for gap in result.coverage_shortfall
    ]


def _nothing_measured_cases(result: ScanResult, _unverified: list[Finding]) -> list[str]:
    detail = (
        f"not one of the {len(result.assessments)} recorded measurement(s) produced a "
        f"value, so this run measured nothing"
    )
    return [
        _error_case(
            "guardana.nothing_measured", "guardana.coverage", "nothing was measured", detail
        )
    ]


def _error_cases(result: ScanResult, _unverified: list[Finding]) -> list[str]:
    """`<error>` rather than `<failure>`: CI reads the first as "could not run"."""
    return [
        _error_case(e.source, f"guardana.{e.stage}", "check did not run", e.reason)
        for e in result.errors
    ]


def _unverified_cases(result: ScanResult, unverified: list[Finding]) -> list[str]:
    """One error for the checks that declined while others concluded.

    Each declined check is honestly a `<skipped>`, and a suite of them beside a few passes
    renders as `failures="0"`, which every dashboard reads as a pass. A run that verified
    nothing already says so, and a declined suite rule is its own testcase.
    """
    if not unverified or result.verified_nothing:
        return []
    detail = (
        f"{len(unverified)} check(s) ran and could not reach a verdict, "
        f"so what they cover was not established"
    )
    return [
        _error_case(
            "guardana.unverified", "guardana.coverage", "some checks reached no verdict", detail
        )
    ]


def _named_elsewhere(_result: ScanResult, _unverified: list[Finding]) -> list[str]:
    return []


_OPEN_CASES: dict[OpenQuestion, Callable[[ScanResult, list[Finding]], list[str]]] = {
    OpenQuestion.STOPPED: _stopped_cases,
    OpenQuestion.NOTHING_VERIFIED: _nothing_verified_cases,
    OpenQuestion.COVERAGE_SHORTFALL: _shortfall_cases,
    OpenQuestion.NOTHING_MEASURED: _nothing_measured_cases,
    # Each declined suite is already an `<error>` testcase of its own.
    OpenQuestion.SUITE_DECLINED: _named_elsewhere,
    OpenQuestion.ERRORS: _error_cases,
    OpenQuestion.UNVERIFIED: _unverified_cases,
    # A skip is an error only when the recorded gate refused the run over it.
    OpenQuestion.SKIPPED: _named_elsewhere,
}


def _refusal_case(result: ScanResult, gate: GateOutcome) -> str:
    return _error_case(
        "guardana.skipped" if refused_skips(result, gate) else "guardana.gate",
        "guardana.run",
        "the gate refused the run",
        refusal_clause(result, gate),
    )


def _subject(result: ScanResult, rule_id: str) -> str:
    """Name what a suite measured, from its assessments; a suite that recorded none has none."""
    refs = (a.subject_ref for a in result.assessments if a.rule_id == rule_id)
    return next(refs, "guardana.suite")


def _suite_case(rule_id: str, summary: SuiteSummary, subject: str) -> str:
    """Write one testcase for a suite: empty on a pass, a failure below its bar, an error declined.

    Declined is an error rather than a skip: its gate is a demand its author wrote.
    """
    statement = _text(describe(summary))
    verdict = ""
    if summary.outcome is SuiteOutcome.FAIL:
        verdict = f'      <failure message="suite below its bar">{statement}</failure>\n'
    elif summary.outcome is SuiteOutcome.INCONCLUSIVE:
        verdict = f'      <error message="suite declined">{_text(summary.reason or "")}</error>\n'
    return (
        f"    <testcase name={_attr(rule_id)} classname={_attr(subject)}>\n"
        f"{verdict}"
        f"      <system-out>{statement}</system-out>\n"
        f"    </testcase>"
    )


def unfinished_document(case: str, message: str, detail: str) -> str:
    """Return a JUnit document for a run that produced no result: one error testcase.

    Written where a CI step reads a report whatever happened, so a refused or interrupted
    run is red in the test view rather than absent from it, which a reporter shows as
    nothing to complain about.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<testsuite name="guardana" tests="1" failures="0" skipped="0" errors="1">\n'
        f"{_error_case(case, 'guardana.run', message, detail)}\n</testsuite>"
    )
