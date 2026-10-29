"""Pricing the judge calls a run adds to its target requests, or saying they cannot be priced.

Each budgeted judge counts its calls on a meter of its own under the same request
ceiling as the target, so a plan that priced the target alone said a judge-graded
run fit a budget the judge then exhausted.
"""

from collections.abc import Iterable, Mapping, Sequence

from guardana.core.budget import Budgets
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.exchange import Exchange
from guardana.core.plan import RunPlan, build_plan
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind

_JUDGE_METER = frozenset({"llm_judge", "reference_judge"})


class _Graded(Rule):
    """An endpoint rule sending `requests` and grading `verdicts`, as it declares."""

    def __init__(self, rule_id: str, verdicts: Mapping[str, int] | None, requests: int = 1) -> None:
        self.meta = RuleMeta(
            rule_id,
            rule_id,
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )
        self._verdicts = verdicts
        self._requests = requests

    @property
    def estimated_requests(self) -> int:
        return self._requests

    @property
    def graded_verdicts(self) -> Mapping[str, int] | None:
        return self._verdicts

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _Unpriced(Evaluator):
    """A third-party grader that never says what a verdict costs."""

    id = "acme.grader"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        return Verdict("pass", 0.5, "unpriced", self.id)


def _judge(prompt: str) -> str:
    raise AssertionError("a plan must not ask the judge anything")


def _plan(
    *rules: Rule,
    samples: int = 1,
    judged: bool = True,
    extra: Sequence[Evaluator] = (),
    meters: Sequence[frozenset[str]] | None = (_JUDGE_METER,),
    max_requests: int | None = None,
) -> RunPlan:
    registry = Registry()
    registry.register_evaluator(KeywordEvaluator())
    if judged:
        registry.register_evaluator(LlmJudgeEvaluator(_judge, min_agreement=samples))
        registry.register_evaluator(ReferenceJudgeEvaluator(_judge, min_agreement=samples))
    for evaluator in extra:
        registry.register_evaluator(evaluator)
    for rule in rules:
        registry.register_rule(rule)
    profile = Profile("t", Policy(), budgets=Budgets(max_requests=max_requests))
    target = EndpointTarget("http://x", "m")
    return build_plan(registry, profile, target, judge_meters=meters)


def test_verdicts_are_priced_at_the_samples_each_one_asks_for() -> None:
    plan = _plan(_Graded("acme.suite", {"reference_judge": 90}, requests=90), samples=3)

    judge = plan.judge
    assert judge is not None
    assert judge.max_calls == 270
    assert [m.max_calls for m in judge.meters] == [270]
    assert judge.is_complete
    assert plan.max_requests == 90, "judge calls are not target requests"


def test_a_judge_over_the_request_ceiling_does_not_fit_though_the_target_does() -> None:
    plan = _plan(
        _Graded("acme.suite", {"reference_judge": 90}, requests=90), samples=3, max_requests=100
    )

    assert plan.max_requests <= 100
    assert plan.exceeds_budget is True


def test_two_judges_on_one_meter_are_summed_before_the_ceiling() -> None:
    plan = _plan(
        _Graded("acme.a", {"llm_judge": 60}),
        _Graded("acme.b", {"reference_judge": 60}),
        max_requests=100,
    )

    assert plan.judge is not None
    assert [m.max_calls for m in plan.judge.meters] == [120]
    assert plan.exceeds_budget is True


def test_separate_meters_are_each_held_to_the_ceiling_on_their_own() -> None:
    plan = _plan(
        _Graded("acme.a", {"llm_judge": 60}),
        _Graded("acme.b", {"reference_judge": 60}),
        meters=(frozenset({"llm_judge"}), frozenset({"reference_judge"})),
        max_requests=100,
    )

    assert plan.judge is not None
    assert plan.judge.max_calls == 120
    assert plan.exceeds_budget is False


def test_a_rule_of_unknown_grading_with_a_judge_configured_never_claims_to_fit() -> None:
    plan = _plan(_Graded("acme.opaque", None), max_requests=10_000)

    assert plan.judge is not None
    assert plan.judge.unknown_cost == ("acme.opaque",)
    assert not plan.is_complete
    assert plan.exceeds_budget is True


def test_unknown_grading_with_no_judge_configured_is_named_but_exhausts_nothing() -> None:
    plan = _plan(_Graded("acme.opaque", None), judged=False, meters=(), max_requests=10_000)

    assert plan.judge is not None
    assert plan.judge.unknown_cost == ("acme.opaque",)
    assert not plan.is_complete
    assert plan.exceeds_budget is False


def test_an_unmetered_grader_of_unknown_cost_is_named_but_does_not_flip_the_fit() -> None:
    plan = _plan(_Graded("acme.graded", {"acme.grader": 5}), extra=[_Unpriced()], max_requests=100)

    assert plan.judge is not None
    assert plan.judge.unknown_cost == ("acme.graded",)
    assert not plan.is_complete
    assert plan.exceeds_budget is False


def test_an_evaluator_nobody_registered_is_of_unknown_cost() -> None:
    plan = _plan(_Graded("acme.graded", {"llm_judge": 5}), judged=False, meters=())

    assert plan.judge is not None
    assert plan.judge.unknown_cost == ("acme.graded",)


def test_a_rule_that_grades_in_its_own_code_is_priced_at_no_judge_calls() -> None:
    plan = _plan(_Graded("acme.self", {}), _Graded("acme.kw", {"keyword": 4}), max_requests=10)

    assert plan.judge is not None
    assert plan.judge.max_calls == 0
    assert plan.judge.is_complete
    assert plan.is_complete
    assert plan.exceeds_budget is False


def test_a_plan_that_does_not_price_judges_is_unchanged_by_them() -> None:
    plan = _plan(_Graded("acme.opaque", None), meters=None, max_requests=10)

    assert plan.judge is None
    assert plan.is_complete
    assert plan.exceeds_budget is False
