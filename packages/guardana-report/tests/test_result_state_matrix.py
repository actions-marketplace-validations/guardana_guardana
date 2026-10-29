"""Every output agrees with the gate on a run that is not a pass.

One row per `OpenQuestion`, each a result exhibiting exactly that question, rendered
through every registered format under the default policy and under a release bar. A
member added to the enum without a row fails `test_every_open_question_has_a_row`, so
a new way for a run to leave its question open cannot reach the renderers unexamined.
"""

import json
from typing import Any
from xml.etree.ElementTree import Element, fromstring

import pytest
from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.gate import (
    GateOutcome,
    OpenQuestion,
    exit_code_for,
    gate_outcome,
    open_questions,
)
from guardana.core.manifest.records import SuiteOutcome
from guardana.core.profile.model import FailOn, Policy
from guardana.core.report import (
    CheckError,
    CoverageShortfall,
    Evidence,
    Finding,
    ScanResult,
    ShortfallKind,
    StopReason,
)
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.severity import Severity
from guardana.core.testing import manifest_for
from guardana.core.testing.manifests import suite_summary
from guardana.report import RENDERER_NAMES, get_renderer

_RAN = ("acme.check",)

_ROWS: dict[OpenQuestion, ScanResult] = {
    OpenQuestion.STOPPED: ScanResult((), _RAN, (), stopped_by=StopReason.BUDGET_EXHAUSTED),
    OpenQuestion.NOTHING_VERIFIED: ScanResult((), (), ()),
    OpenQuestion.COVERAGE_SHORTFALL: ScanResult(
        (),
        _RAN,
        (),
        coverage_shortfall=(
            CoverageShortfall(
                kind=ShortfallKind.MISSING_DIMENSION,
                name="approval",
                detail="the policy requires approval spans and the trace records none",
            ),
        ),
    ),
    OpenQuestion.NOTHING_MEASURED: ScanResult(
        (),
        _RAN,
        (),
        assessments=(
            Assessment(
                case_id="acme.check#0",
                assessor="keyword",
                subject_ref="http://x#m",
                status=AssessmentStatus.INCONCLUSIVE,
                rule_id="acme.check",
            ),
        ),
    ),
    OpenQuestion.SUITE_DECLINED: ScanResult(
        (),
        ("acme.suite",),
        (),
        suites={
            "acme.suite": suite_summary(
                outcome=SuiteOutcome.INCONCLUSIVE,
                reason="the grader could not be calibrated",
            )
        },
    ),
    OpenQuestion.ERRORS: ScanResult(
        (),
        _RAN,
        (),
        errors=(CheckError(source="acme.broken", stage="run", reason="ValueError: typo"),),
    ),
    OpenQuestion.UNVERIFIED: ScanResult(
        (),
        ("acme.check", "acme.graded"),
        (),
        unverified=(
            Finding(
                "acme.graded",
                Severity.HIGH,
                "could not grade",
                (),
                "http://x#m",
                Evidence(summary="no model reply to inspect"),
            ),
        ),
    ),
    OpenQuestion.SKIPPED: ScanResult(
        (),
        _RAN,
        (
            SkippedRule(
                rule_id="acme.tools",
                reason=SkipReason.MISSING_CAPABILITY,
                missing=("list_tools",),
                detail="the target exposes no tool surface",
            ),
        ),
    ),
}

_INTERRUPTED = ScanResult((), _RAN, (), stopped_by=StopReason.INTERRUPTED)
_CLEAN = ScanResult((), _RAN, ())

_CASES: dict[str, tuple[ScanResult, OpenQuestion | None]] = {
    **{question.value: (result, question) for question, result in _ROWS.items()},
    "stopped_interrupted": (_INTERRUPTED, OpenQuestion.STOPPED),
    "clean": (_CLEAN, None),
}

_POLICIES = {
    "default": Policy(),
    "release": Policy(
        fail_on=FailOn(severity=Severity.HIGH, fail_on_skipped=True, fail_on_inconclusive=True)
    ),
}

_DESCRIPTOR_PREFIX = {
    OpenQuestion.NOTHING_VERIFIED: "guardana.coverage_shortfall.nothing_verified",
    OpenQuestion.COVERAGE_SHORTFALL: "guardana.coverage_shortfall.",
    OpenQuestion.ERRORS: "guardana.check_error.",
}
"""SARIF descriptor ids that predate the open-question names and are kept for consumers."""


def _descriptor_prefix(question: OpenQuestion) -> str:
    return _DESCRIPTOR_PREFIX.get(question, f"guardana.open_question.{question.value}")


class _Rendered:
    """One result rendered through every registered format, parsed where it is structured."""

    def __init__(self, result: ScanResult, gate: GateOutcome) -> None:
        manifest = manifest_for(result, gate=gate)
        out = {name: get_renderer(name, run=manifest).render(result) for name in RENDERER_NAMES}
        self.human: str = out["human"]
        self.junit: Element = fromstring(out["junit"])  # noqa: S314 — our own output
        sarif = json.loads(out["sarif"])
        self.invocation: dict[str, Any] = sarif["runs"][0]["invocations"][0]
        self.summary: dict[str, Any] = json.loads(out["json"])["run"]["result_summary"]

    @property
    def junit_errors(self) -> int:
        return int(self.junit.get("errors", "0"))

    @property
    def junit_failures(self) -> int:
        return int(self.junit.get("failures", "0"))

    @property
    def notifications(self) -> list[dict[str, Any]]:
        notes: list[dict[str, Any]] = self.invocation["toolExecutionNotifications"]
        return notes

    @property
    def descriptors(self) -> list[str]:
        return [str(note["descriptor"]["id"]) for note in self.notifications]


def _render(case: str, policy: str) -> tuple[_Rendered, GateOutcome, OpenQuestion | None]:
    result, question = _CASES[case]
    gate = gate_outcome(result, _POLICIES[policy])
    return _Rendered(result, gate), gate, question


def test_every_open_question_has_a_row() -> None:
    assert set(_ROWS) == set(OpenQuestion)


@pytest.mark.parametrize("case", sorted(_CASES))
def test_each_row_exhibits_exactly_its_question(case: str) -> None:
    result, question = _CASES[case]

    assert open_questions(result) == (() if question is None else (question,))


_REFUSED = [
    (case, policy)
    for case in sorted(_CASES)
    for policy in sorted(_POLICIES)
    if gate_outcome(_CASES[case][0], _POLICIES[policy]) is not GateOutcome.PASS
]
"""Every row the gate refuses under a policy; the converse is not an invariant by design."""


def test_the_refused_rows_cover_both_policies() -> None:
    assert {policy for _, policy in _REFUSED} == set(_POLICIES)
    assert (OpenQuestion.SKIPPED.value, "release") in _REFUSED


@pytest.mark.parametrize(("case", "policy"), _REFUSED)
def test_no_output_renders_clean_when_the_gate_refused(case: str, policy: str) -> None:
    rendered, gate, _ = _render(case, policy)

    assert gate is not GateOutcome.PASS
    assert "✓" not in rendered.human
    assert rendered.junit_errors + rendered.junit_failures > 0
    assert rendered.invocation["executionSuccessful"] is False
    assert rendered.notifications
    assert rendered.summary["gate"] != GateOutcome.PASS.value


@pytest.mark.parametrize("policy", sorted(_POLICIES))
@pytest.mark.parametrize(
    "case", sorted(c for c, (_, q) in _CASES.items() if q not in (None, OpenQuestion.SKIPPED))
)
def test_every_open_question_but_a_skip_is_named_whatever_the_policy(
    case: str, policy: str
) -> None:
    rendered, _, question = _render(case, policy)
    if question is None:
        raise TypeError(f"{case} has no question to name")

    assert "✓" not in rendered.human
    assert "not an all-clear" in rendered.human
    assert rendered.junit_errors > 0
    assert rendered.invocation["executionSuccessful"] is False
    prefix = _descriptor_prefix(question)
    assert any(d.startswith(prefix) for d in rendered.descriptors), rendered.descriptors


@pytest.mark.parametrize("policy", sorted(_POLICIES))
def test_a_clean_complete_run_is_clean_in_every_output(policy: str) -> None:
    rendered, gate, _ = _render("clean", policy)

    assert gate is GateOutcome.PASS
    assert "✓ No findings." in rendered.human
    assert (rendered.junit_errors, rendered.junit_failures) == (0, 0)
    assert rendered.invocation["executionSuccessful"] is True
    assert rendered.notifications == []
    assert rendered.summary["gate"] == GateOutcome.PASS.value


def test_a_skip_the_policy_accepts_leaves_the_run_clean() -> None:
    rendered, gate, _ = _render(OpenQuestion.SKIPPED.value, "default")

    assert gate is GateOutcome.PASS
    assert "✓ No findings." in rendered.human
    assert rendered.junit_errors == 0
    assert rendered.invocation["executionSuccessful"] is True


def test_a_skip_the_gate_refused_is_named_in_every_output() -> None:
    rendered, gate, _ = _render(OpenQuestion.SKIPPED.value, "release")

    assert gate is GateOutcome.INDETERMINATE
    assert "1 rule(s) were skipped" in rendered.human
    assert "indeterminate" in rendered.human
    names = [case.get("name") for case in rendered.junit.iter("testcase")]
    assert "guardana.skipped" in names
    assert "guardana.open_question.skipped" in rendered.descriptors


def test_a_refused_gate_with_nothing_to_show_for_it_is_still_not_clean() -> None:
    rendered = _Rendered(_CLEAN, GateOutcome.INDETERMINATE)

    assert "✓" not in rendered.human
    assert "the gate is indeterminate" in rendered.human
    assert rendered.junit_errors == 1
    assert rendered.invocation["executionSuccessful"] is False
    assert rendered.descriptors == ["guardana.open_question.gate"]


@pytest.mark.parametrize(
    ("policy", "stated"),
    [("default", "the gate is pass"), ("release", "the gate is indeterminate")],
)
def test_sarif_says_how_many_checks_reached_no_verdict_and_what_the_gate_made_of_it(
    policy: str, stated: str
) -> None:
    rendered, _, _ = _render(OpenQuestion.UNVERIFIED.value, policy)

    [note] = [
        n
        for n in rendered.notifications
        if n["descriptor"] == {"id": "guardana.open_question.unverified"}
    ]
    text = str(note["message"]["text"])
    assert text.startswith("1 check(s) ran and could not reach a verdict")
    assert stated in text


@pytest.mark.parametrize("policy", sorted(_POLICIES))
@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_sarif_exit_code_is_the_one_the_json_gate_implies(case: str, policy: str) -> None:
    rendered, _, _ = _render(case, policy)
    stopped = rendered.summary.get("stopped_by")

    expected = exit_code_for(
        GateOutcome(rendered.summary["gate"]),
        None if stopped is None else StopReason(stopped),
    )
    assert rendered.invocation["exitCode"] == expected


def test_findings_beside_a_skip_the_gate_refused_still_name_the_refusal() -> None:
    # A MEDIUM finding does not fail a HIGH bar, so the skip is the whole reason the
    # release gate refused; the findings above it must not stand in for an all-clear.
    below_the_bar = Finding(
        "acme.lead", Severity.MEDIUM, "a lead", (), "src/app.py", Evidence(summary="a lead")
    )
    result = ScanResult((below_the_bar,), _RAN, _ROWS[OpenQuestion.SKIPPED].rules_skipped)
    gate = gate_outcome(result, _POLICIES["release"])

    rendered = _Rendered(result, gate)

    assert gate is GateOutcome.INDETERMINATE
    assert "⚠ 1 rule(s) were skipped and the gate refused the run" in rendered.human
    assert rendered.junit_errors == 1
    assert rendered.descriptors == [
        "guardana.open_question.skipped",
        "guardana.skipped.missing_capability",
    ]


def test_a_failed_gate_no_rendered_fact_explains_is_named_as_the_gate() -> None:
    rendered = _Rendered(_ROWS[OpenQuestion.SKIPPED], GateOutcome.FAIL)

    assert "✓" not in rendered.human
    assert "the gate is fail" in rendered.human
    assert rendered.descriptors == [
        "guardana.open_question.gate",
        "guardana.skipped.missing_capability",
    ]


def test_sarif_says_so_when_the_saved_run_recorded_no_gate() -> None:
    result = _ROWS[OpenQuestion.UNVERIFIED]
    sarif = json.loads(get_renderer("sarif", run=manifest_for(result, gate=None)).render(result))

    [note] = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert note["message"]["text"].endswith("; the run recorded no gate")


@pytest.mark.parametrize("name", ["human", "junit", "sarif"])
def test_a_gate_given_without_a_manifest_still_refuses_to_render_clean(name: str) -> None:
    # A monitor cycle writes no run document; its alert passes the gate it computed.
    result = _ROWS[OpenQuestion.SKIPPED]

    text = get_renderer(name, gate=GateOutcome.INDETERMINATE).render(result)

    assert "1 rule(s) were skipped and the gate refused the run" in text
    assert "✓" not in text


def test_a_gate_given_without_a_manifest_is_written_into_the_json_document() -> None:
    """A manifestless JSON document with empty channels must still say the run was refused."""
    result = _ROWS[OpenQuestion.STOPPED]

    document = json.loads(get_renderer("json", gate=GateOutcome.INDETERMINATE).render(result))

    assert document["gate"] == "indeterminate"
    assert document["stopped_by"] == "budget_exhausted"
    assert document["findings"] == []


def test_a_json_document_with_no_manifest_and_no_gate_says_no_gate_was_recorded() -> None:
    document = json.loads(get_renderer("json").render(_ROWS[OpenQuestion.STOPPED]))

    assert document["gate"] is None
    assert document["stopped_by"] == "budget_exhausted"
