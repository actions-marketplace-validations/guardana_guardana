"""An evaluator's `pass` on an exchange with no reply text is graded `inconclusive` by the engine.

A third-party evaluator that only checks for something bad finds nothing bad in an
empty reply. The built-ins decline on their own; the engine enforces it for every
evaluator at every place it grades, so an endpoint that answers with nothing cannot
read as a clean run whoever wrote the grader.
"""

from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import ClassVar

import pytest
from guardana.core.assessment import AssessmentStatus
from guardana.core.evaluator.base import Evaluator, Expectation, Outcome, Verdict, grade
from guardana.core.exchange import Exchange
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.rule import Rule
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep
from guardana.core.rule.suite_rule import SuiteCase, SuiteRule
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.rule.yaml_rule import YamlRule
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.suite import SuiteGate
from guardana.core.target import Capability, EndpointTarget, TargetKind
from guardana.core.target.endpoint import ChatMessage, ToolCallReply, ToolSpec
from guardana.core.trajectory import StaticToolDouble, ToolOffer

_EVALUATOR = "acme.no_at_sign"

_META = RuleMeta(
    "acme.empty_reply",
    "empty reply",
    Severity.HIGH,
    TargetKind.ENDPOINT,
    required_capabilities=frozenset({Capability.CHAT}),
    evaluator=_EVALUATOR,
)


class _Fixed(Evaluator):
    """Returns the same outcome for every exchange, whatever it carries."""

    id = _EVALUATOR
    deterministic: ClassVar[bool] = True

    def __init__(self, outcome: Outcome) -> None:
        self._outcome = outcome

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        return Verdict(self._outcome, 0.9, f"always {self._outcome}", self.id)


class _Says:
    """A model that answers every turn with the same text and never calls a tool."""

    def __init__(self, text: str) -> None:
        self._text = text

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return self._text

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        return ToolCallReply(text=self._text, tool_calls=())


def _single_turn() -> Rule:
    return YamlRule(meta=_META, prompts=("Write me an email address.",), expectation=Expectation())


def _scenario_step() -> Rule:
    return ScenarioRule(
        meta=replace(_META, evaluator=None),
        steps=(ScenarioStep("hello", None, None), ScenarioStep("again", _EVALUATOR, Expectation())),
    )


def _scenario_conversation() -> Rule:
    return ScenarioRule(
        meta=replace(_META, evaluator=None),
        steps=(ScenarioStep("hello", None, None), ScenarioStep("again", None, None)),
        conversation_evaluator=_EVALUATOR,
        conversation_expect=Expectation(),
    )


def _suite() -> Rule:
    cases = tuple(
        SuiteCase(f"c{n}", (ChatMessage(role="user", content=f"Q{n}?"),), Expectation())
        for n in range(3)
    )
    return SuiteRule(
        meta=_META,
        cases=cases,
        gate=SuiteGate(min_pass_rate=0.9, min_sample=1),
        dataset="answers@1",
        dataset_digest="sha256:0",
    )


def _trajectory() -> Rule:
    return TrajectoryRule(
        meta=replace(
            _META, required_capabilities=frozenset({Capability.CHAT, Capability.CALL_TOOLS})
        ),
        task="Summarise the note.",
        tools=(ToolOffer(ToolSpec("read_file", "Read a file."), StaticToolDouble("A note.")),),
        max_steps=3,
        expectation=Expectation(),
    )


_TEXT_RULES = {
    "single-turn": _single_turn,
    "scenario step": _scenario_step,
    "scenario conversation": _scenario_conversation,
    "suite": _suite,
}


def _run(rule: Rule, outcome: Outcome, reply: str) -> ScanResult:
    registry = Registry()
    registry.register_rule(rule)
    registry.register_evaluator(_Fixed(outcome))
    target = EndpointTarget("http://x", "m", transport=_Says(reply))
    return Runner(registry=registry, profile=Profile("t", Policy())).run(target)


@pytest.mark.parametrize("reply", ["", "  \n\t"], ids=["empty", "whitespace"])
@pytest.mark.parametrize("build", _TEXT_RULES.values(), ids=_TEXT_RULES.keys())
def test_a_pass_on_no_reply_is_ungraded_not_clean(build: Callable[[], Rule], reply: str) -> None:
    result = _run(build(), "pass", reply)

    assert result.findings == ()
    assert result.errors == ()
    assert len(result.unverified) == 1
    unverified = result.unverified[0].verdict
    assert unverified is not None
    assert unverified.outcome == "inconclusive"
    assert unverified.evaluator_id == _EVALUATOR
    assert result.assessments
    assert {a.status for a in result.assessments} == {AssessmentStatus.INCONCLUSIVE}
    policy = Policy(fail_on=FailOn(fail_on_inconclusive=True, fail_on_skipped=True))
    assert gate_outcome(result, policy) is GateOutcome.INDETERMINATE


@pytest.mark.parametrize("build", _TEXT_RULES.values(), ids=_TEXT_RULES.keys())
def test_a_fail_on_no_reply_stays_a_finding(build: Callable[[], Rule]) -> None:
    result = _run(build(), "fail", "")

    assert len(result.findings) == 1
    verdict = result.findings[0].verdict
    assert verdict is not None
    assert verdict.outcome == "fail"
    assert result.unverified == ()


@pytest.mark.parametrize("build", _TEXT_RULES.values(), ids=_TEXT_RULES.keys())
def test_a_pass_on_a_reply_stands(build: Callable[[], Rule]) -> None:
    result = _run(build(), "pass", "No email address here.")

    assert result.findings == ()
    assert result.unverified == ()
    assert {a.status for a in result.assessments} == {AssessmentStatus.MEASURED}
    assert gate_outcome(result, Policy(fail_on=FailOn(fail_on_inconclusive=True))) is (
        GateOutcome.PASS
    )


def test_an_agent_run_that_ended_without_text_may_still_pass() -> None:
    """A tool-call grader reads the run, not the prose; a run with no final text can be clean."""
    result = _run(_trajectory(), "pass", "")

    assert result.findings == ()
    assert result.unverified == ()
    assert result.errors == ()
    assert result.assessments
    assert {a.status for a in result.assessments} == {AssessmentStatus.MEASURED}
    assert gate_outcome(result, Policy(fail_on=FailOn(fail_on_inconclusive=True))) is (
        GateOutcome.PASS
    )


def test_grade_keeps_the_evaluator_and_names_the_missing_reply() -> None:
    exchange = Exchange((ChatMessage(role="user", content="hi"), ChatMessage("assistant", "")))

    verdict = grade(_Fixed("pass"), exchange, Expectation())

    assert verdict.outcome == "inconclusive"
    assert verdict.confidence == 0.0
    assert verdict.evaluator_id == _EVALUATOR
    assert verdict.measurement is None
    assert "no reply" in verdict.rationale


def test_grade_leaves_an_inconclusive_and_a_fail_untouched() -> None:
    exchange = Exchange.single_reply("")

    outcomes: tuple[Outcome, ...] = ("fail", "inconclusive")
    for outcome in outcomes:
        evaluator = _Fixed(outcome)
        assert grade(evaluator, exchange, Expectation()) == evaluator.evaluate(
            exchange, Expectation()
        )
