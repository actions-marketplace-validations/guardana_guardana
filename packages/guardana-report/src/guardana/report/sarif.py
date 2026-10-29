import json
from collections.abc import Callable
from datetime import UTC, datetime

from guardana.core.gate import (
    GateOutcome,
    OpenQuestion,
    declined_suites,
    exit_code_for,
    open_questions,
)
from guardana.core.manifest import RunManifest
from guardana.core.report import (
    CheckError,
    CoverageShortfall,
    Finding,
    ScanResult,
    SkippedRule,
    split_ref,
)
from guardana.core.severity import Severity
from guardana.report._refusal import (
    recorded_gate,
    refusal_clause,
    refused_skips,
    unnamed_refusal,
)

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_HELP_URI = "https://github.com/guardana/guardana"


def _level(finding: Finding) -> str:
    return _LEVEL.get(finding.severity, "note")


def _location(finding: Finding) -> dict[str, object]:
    # A repo-relative uri and an integer region.startLine are what GitHub code
    # scanning needs to attach an alert to a source line — not the line glued onto
    # the uri. An endpoint ref ("url#model") has no line and stays a bare uri.
    path, line = split_ref(finding.target_ref)
    physical: dict[str, object] = {"artifactLocation": {"uri": path}}
    if line is not None:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _sarif_result(
    finding: Finding,
    *,
    rule_index: int,
    level: str,
    kind: str | None = None,
    suppressed: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": f"{finding.title}: {finding.evidence.summary}"},
        "locations": [_location(finding)],
        # A stable fingerprint lets code scanning track an alert across runs even
        # as line numbers move — we already compute one, so emit it.
        "partialFingerprints": {"guardanaFingerprint/v1": finding.fingerprint},
    }
    if kind is not None:
        result["kind"] = kind
    if suppressed:
        # SARIF's native representation of a baselined finding: still reported,
        # but marked suppressed so a consumer (GitHub code scanning) doesn't alert.
        result["suppressions"] = [{"kind": "external"}]
    return result


def _driver_rules(
    findings: list[Finding], manifest: RunManifest | None
) -> tuple[list[dict[str, object]], dict[str, int]]:
    """Build `driver.rules[]` (one per distinct rule) and a rule-id → index map.

    Code scanning ignores results whose `ruleId` has no entry in `driver.rules`, so
    an empty `rules[]` (the old behaviour) drops every alert. A rule that repeated
    carries its attempts per case, per rule rather than per run, because a protocol
    check in the same run made one.
    """
    repeated = (
        {}
        if manifest is None
        else {
            r.id: r.trial_summary.trials_per_case
            for r in manifest.rules
            if r.trial_summary is not None
        }
    )
    index: dict[str, int] = {}
    rules: list[dict[str, object]] = []
    for finding in findings:
        if finding.rule_id not in index:
            index[finding.rule_id] = len(rules)
            rule: dict[str, object] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "helpUri": _HELP_URI,
                "defaultConfiguration": {"level": _level(finding)},
            }
            if finding.rule_id in repeated:
                rule["properties"] = {"trialsPerCase": repeated[finding.rule_id]}
            rules.append(rule)
    return rules, index


def _results(result: ScanResult, index: dict[str, int]) -> list[dict[str, object]]:
    confirmed = [
        _sarif_result(f, rule_index=index[f.rule_id], level=_level(f)) for f in result.findings
    ]
    # An unverified check is not a clean pass: surface it as a note flagged for
    # review, never omit it (that would read as "no problem" to a SARIF consumer).
    unverified = [
        _sarif_result(f, rule_index=index[f.rule_id], level="note", kind="review")
        for f in result.unverified
    ]
    waived = [
        _sarif_result(f, rule_index=index[f.rule_id], level=_level(f), suppressed=True)
        for f in result.waived
    ]
    return confirmed + unverified + waived


_EXIT_CODE_DESCRIPTIONS = {
    0: "run completed, policy passed",
    1: "run completed, policy failed",
    2: "result indeterminate",
    4: "target became unavailable or changed under the run, coverage partial",
    6: "budget exhausted, coverage partial",
    7: "run interrupted, partial evidence written",
}


def _utc(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _invocation(
    result: ScanResult, manifest: RunManifest | None, gate: GateOutcome | None
) -> dict[str, object]:
    """Build `runs[].invocations[0]` — SARIF's own place for how the run itself went.

    `executionSuccessful` is what stops a viewer reading an empty result list as
    a clean run, so it is false for every open question the renderers always name,
    each with a notification saying which, and for a refusal the recorded gate made
    over nothing else named. Each rule skipped for want of coverage adds a note that
    leaves it as it is.

    The timestamps and exit code come from the manifest when there is one; SARIF
    marks them optional, and inventing them would be worse than omitting.
    """
    questions = open_questions(result)
    notifications = [note for q in questions for note in _OPEN_NOTES[q](result, manifest, gate)]
    refusal = unnamed_refusal(result, gate, questions)
    if refusal is not None:
        notifications.append(_refusal_notification(result, refusal))
    invocation: dict[str, object] = {
        "executionSuccessful": not notifications,
        "toolExecutionNotifications": [*notifications, *map(_skip_notification, _gaps(result))],
    }
    if manifest is None:
        return invocation
    summary = manifest.result_summary
    code = exit_code_for(summary.gate or GateOutcome.INDETERMINATE, summary.stopped_by)
    invocation["exitCode"] = code
    invocation["exitCodeDescription"] = _EXIT_CODE_DESCRIPTIONS[code]
    started, ended = _utc(manifest.started_at), _utc(manifest.completed_at)
    if started is not None:
        invocation["startTimeUtc"] = started
    if ended is not None:
        invocation["endTimeUtc"] = ended
    return invocation


class SarifRenderer:
    """SARIF 2.1.0 — what GitHub code scanning ingests."""

    name = "sarif"

    def __init__(self, run: RunManifest | None = None, gate: GateOutcome | None = None) -> None:
        self._run = run
        self._gate = recorded_gate(run, gate)

    def render(self, result: ScanResult) -> str:
        """Render one scan result to text."""
        every = [*result.findings, *result.unverified, *result.waived]
        rules, index = _driver_rules(every, self._run)
        doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Guardana",
                            "informationUri": "https://github.com/guardana/guardana",
                            "rules": rules,
                        }
                    },
                    "results": _results(result, index),
                    "invocations": [_invocation(result, self._run, self._gate)],
                }
            ],
        }
        return json.dumps(doc, indent=2)


def _notification(error: CheckError) -> dict[str, object]:
    return {
        "level": "error",
        "message": {"text": f"{error.source} did not run ({error.stage}): {error.reason}"},
        "descriptor": {"id": f"guardana.check_error.{error.stage}"},
    }


def _coverage_notification(gap: CoverageShortfall) -> dict[str, object]:
    """Say which coverage was missing, not only that the run failed.

    A viewer told an invocation was unsuccessful and not told why has a red mark and
    no next step, which is how a channel stops being read.
    """
    return {
        "level": "error",
        "message": {"text": f"coverage missing ({gap.kind}): {gap.name}: {gap.detail}"},
        "descriptor": {"id": f"guardana.coverage_shortfall.{gap.kind}"},
    }


def _gaps(result: ScanResult) -> list[SkippedRule]:
    return [skip for skip in result.rules_skipped if skip.is_coverage_gap]


def _skip_notification(skip: SkippedRule) -> dict[str, object]:
    """Name a rule that never ran for want of coverage, without failing the invocation.

    The gate decides whether a skip refuses the run; a note keeps an accepted skip from
    vanishing from the document while leaving `executionSuccessful` to that decision.
    """
    return {
        "level": "note",
        "message": {"text": f"{skip.rule_id} was skipped ({skip.reason}): {skip.detail}"},
        "descriptor": {"id": f"guardana.skipped.{skip.reason}"},
        # Not `associatedRule`: that reference must resolve in `driver.rules`, which lists
        # only the rules that produced a result.
        "properties": {"ruleId": skip.rule_id},
    }


def _nothing_verified_notification(ran: int) -> dict[str, object]:
    return {
        "level": "error",
        "message": {
            "text": (
                f"{ran} check(s) ran and not one of them reached a verdict, so this run "
                f"established nothing"
            )
        },
        "descriptor": {"id": "guardana.coverage_shortfall.nothing_verified"},
    }


def _open_question(question: str, text: str, level: str = "error") -> dict[str, object]:
    return {
        "level": level,
        "message": {"text": text},
        "descriptor": {"id": f"guardana.open_question.{question}"},
    }


def _stopped_notes(
    result: ScanResult, _manifest: RunManifest | None, _gate: GateOutcome | None
) -> list[dict[str, object]]:
    text = (
        f"the run stopped early ({result.stopped_by}) before finishing its plan; checks it "
        f"never reached are not in this report"
    )
    return [_open_question(OpenQuestion.STOPPED, text)]


def _nothing_measured_notes(
    result: ScanResult, _manifest: RunManifest | None, _gate: GateOutcome | None
) -> list[dict[str, object]]:
    text = (
        f"not one of the {len(result.assessments)} recorded measurement(s) produced a value, "
        f"so this run measured nothing"
    )
    return [_open_question(OpenQuestion.NOTHING_MEASURED, text)]


def _suite_declined_notes(
    result: ScanResult, _manifest: RunManifest | None, _gate: GateOutcome | None
) -> list[dict[str, object]]:
    declined = [
        f"{rule_id} ({summary.reason})" for rule_id, summary in declined_suites(result).items()
    ]
    text = (
        f"{len(declined)} suite(s) declined to conclude on their pass rate: {'; '.join(declined)}"
    )
    return [_open_question(OpenQuestion.SUITE_DECLINED, text)]


def _unverified_notes(
    result: ScanResult, manifest: RunManifest | None, gate: GateOutcome | None
) -> list[dict[str, object]]:
    """Say how many checks reached no verdict and what the recorded gate made of it.

    Under a policy that accepts them the exit code is `0` beside `executionSuccessful:
    false`, which reads as a contradiction unless the notification states both halves.
    """
    text = f"{len(result.unverified)} check(s) ran and could not reach a verdict"
    if manifest is None and gate is None:
        text += ", so what they cover was not established"
    elif gate is None:
        text += "; the run recorded no gate"
    elif gate is GateOutcome.PASS:
        text += "; the gate is pass, so the policy accepted the run without them"
    else:
        text += f"; the gate is {gate}"
    return [_open_question(OpenQuestion.UNVERIFIED, text, level="warning")]


def _named_by_refusal(
    _result: ScanResult, _manifest: RunManifest | None, _gate: GateOutcome | None
) -> list[dict[str, object]]:
    return []


_OPEN_NOTES: dict[
    OpenQuestion,
    Callable[[ScanResult, RunManifest | None, GateOutcome | None], list[dict[str, object]]],
] = {
    OpenQuestion.STOPPED: _stopped_notes,
    OpenQuestion.NOTHING_VERIFIED: lambda r, _m, _g: [
        _nothing_verified_notification(r.rules_run_count)
    ],
    OpenQuestion.COVERAGE_SHORTFALL: lambda r, _m, _g: [
        _coverage_notification(gap) for gap in r.coverage_shortfall
    ],
    OpenQuestion.NOTHING_MEASURED: _nothing_measured_notes,
    OpenQuestion.SUITE_DECLINED: _suite_declined_notes,
    OpenQuestion.ERRORS: lambda r, _m, _g: [_notification(e) for e in r.errors],
    OpenQuestion.UNVERIFIED: _unverified_notes,
    # A skip is named only when the recorded gate refused the run over it.
    OpenQuestion.SKIPPED: _named_by_refusal,
}


def _refusal_notification(result: ScanResult, gate: GateOutcome) -> dict[str, object]:
    question = "skipped" if refused_skips(result, gate) else "gate"
    return _open_question(question, refusal_clause(result, gate))
