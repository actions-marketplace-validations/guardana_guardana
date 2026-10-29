"""Each declarative rule says how many verdicts it grades per evaluator, and grades no more.

`guardana plan probe` prices judge calls from these counts. Each count is checked
by running the rule against a model double with a counting evaluator in its
context, so a declaration cannot drift away from what `run` does.
"""

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import replace

from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep
from guardana.core.rule.suite_rule import SuiteCase, SuiteRule
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.rule.yaml_rule import YamlRule
from guardana.core.severity import Severity
from guardana.core.suite import SuiteGate
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.target.endpoint import ChatMessage, ToolCallReply, ToolSpec
from guardana.core.trajectory import StaticToolDouble, ToolOffer

_META = RuleMeta(
    "acme.graded",
    "graded",
    Severity.HIGH,
    TargetKind.ENDPOINT,
    required_capabilities=frozenset({Capability.CHAT}),
)


class _Counted(Evaluator):
    """Passes everything under a borrowed id, and counts every verdict it is asked for."""

    def __init__(self, evaluator_id: str, tally: Counter[str]) -> None:
        self.id = evaluator_id
        self._tally = tally

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        self._tally[self.id] += 1
        return Verdict("pass", 0.9, "counted", self.id)


class _Answers:
    """A model that answers every turn in prose and never calls a tool."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return "Done."

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        return ToolCallReply(text="Done.", tool_calls=())


class _Undeclared(Rule):
    meta = _META

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def _graded(rule: Rule, *evaluator_ids: str) -> Counter[str]:
    """Run `rule` once and count the verdicts each evaluator was asked for."""
    tally: Counter[str] = Counter()
    ctx = RuleContext(evaluators={e: _Counted(e, tally) for e in evaluator_ids})
    target = EndpointTarget("http://x", "m", transport=_Answers())
    list(rule.run(target, ctx))
    return tally


def _trials(rule: Rule, trials: int) -> Rule:
    repeated = rule.with_trials(trials)
    if repeated is None:
        raise TypeError(f"{rule.meta.id} does not repeat")
    return repeated


def test_a_rule_that_says_nothing_grades_an_unknown_number_of_verdicts() -> None:
    assert _Undeclared().graded_verdicts is None


def test_a_prompt_rule_grades_every_prompt_in_every_trial() -> None:
    rule = _trials(
        YamlRule(
            meta=replace(_META, evaluator="llm_judge"),
            prompts=("a", "b", "c"),
            expectation=Expectation(goal="g"),
        ),
        2,
    )

    assert rule.graded_verdicts == {"llm_judge": 6}
    assert _graded(rule, "llm_judge") == rule.graded_verdicts


def test_a_suite_grades_every_case_in_every_trial() -> None:
    cases = tuple(
        SuiteCase(f"c{n}", (ChatMessage(role="user", content=f"Q{n}?"),), Expectation(goal="g"))
        for n in range(30)
    )
    rule = _trials(
        SuiteRule(
            meta=replace(_META, evaluator="reference_judge"),
            cases=cases,
            gate=SuiteGate(min_pass_rate=0.9, min_sample=1),
            dataset="answers@1",
            dataset_digest="sha256:0",
        ),
        3,
    )

    assert rule.graded_verdicts == {"reference_judge": 90}
    assert _graded(rule, "reference_judge") == rule.graded_verdicts


def test_a_scenario_counts_its_conversation_grade_and_each_step_by_its_own_evaluator() -> None:
    rule = _trials(
        ScenarioRule(
            meta=_META,
            steps=(
                ScenarioStep("set up", None, None),
                ScenarioStep("push", "keyword", Expectation()),
                ScenarioStep("push again", "keyword", Expectation()),
                ScenarioStep("close", "canary", Expectation(canary="C")),
            ),
            conversation_evaluator="llm_judge",
            conversation_expect=Expectation(goal="g"),
        ),
        3,
    )

    assert rule.graded_verdicts == {"keyword": 6, "canary": 3, "llm_judge": 3}
    assert _graded(rule, "keyword", "canary", "llm_judge") == rule.graded_verdicts


def test_a_scenario_graded_only_as_a_whole_is_not_priced_at_nothing() -> None:
    rule = ScenarioRule(
        meta=_META,
        steps=(ScenarioStep("one", None, None), ScenarioStep("two", None, None)),
        conversation_evaluator="llm_judge",
        conversation_expect=Expectation(goal="g"),
    )

    assert rule.graded_verdicts == {"llm_judge": 1}
    assert _graded(rule, "llm_judge") == rule.graded_verdicts


def _trajectory(*, then_task: str | None) -> TrajectoryRule:
    return TrajectoryRule(
        meta=replace(_META, evaluator="llm_judge"),
        task="Summarise the note.",
        tools=(ToolOffer(ToolSpec("read_file", "Read a file."), StaticToolDouble("A note.")),),
        max_steps=3,
        expectation=Expectation(goal="g"),
        then_task=then_task,
    )


def test_a_two_session_trajectory_grades_both_sessions_in_every_trial() -> None:
    rule = _trials(_trajectory(then_task="What did the note say?"), 3)

    assert rule.graded_verdicts == {"llm_judge": 6}
    assert _graded(rule, "llm_judge") == rule.graded_verdicts


def test_a_one_session_trajectory_grades_once_per_trial() -> None:
    rule = _trials(_trajectory(then_task=None), 2)

    assert rule.graded_verdicts == {"llm_judge": 2}
    assert _graded(rule, "llm_judge") == rule.graded_verdicts
