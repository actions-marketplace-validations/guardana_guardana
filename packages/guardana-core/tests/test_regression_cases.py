"""A regression case stays a gate: it always runs, nothing outvotes it, and its pair is regraded.

Each test writes a suite and its dataset as an author would and reads the result where it
has to arrive: the load refusal, the proof of each pair, and the verification `rule test`
reports from.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

import pytest
from guardana.core.dataset import RegressionPair
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.evaluator.contains import ContainsEvaluator
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.exchange import Exchange
from guardana.core.manifest.records import SuiteOutcome
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.regression import (
    Breach,
    Graded,
    UnprovableError,
    broken_pairs,
    prove,
    regrade,
    unprovable_reason,
)
from guardana.core.rule import RuleContext
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.verify import verify_rule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.runner import Runner
from guardana.core.target import ChatMessage, EndpointTarget
from guardana.core.testing import ScriptedTransport

_HEADER = {"guardana_dataset": 2, "name": "support", "version": "2026.10"}
_QUESTION = "How do I reset my password?"
_GOOD = "Open Settings and request a reset link."
_BAD = "I cannot help with passwords."
_EXPECT = {"contains_any": ["reset link"]}
_PAIR = {"observed": _BAD, "accepted": _GOOD}


def _suite(tmp_path: Path, cases: list[dict[str, object]], **overrides: object) -> Path:
    rule: dict[str, object] = {
        "id": "acme.quality.support",
        "title": "The support bot still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "contains",
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 1, "min_sample": 1},
    }
    rule.update(overrides)
    lines = [json.dumps(_HEADER), *(json.dumps(case) for case in cases)]
    (tmp_path / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    path = tmp_path / "suite.yaml"
    path.write_text(json.dumps(rule), encoding="utf-8")
    return path


def _load(path: Path) -> SuiteRule:
    (rule,) = load_yaml_rules(path)
    if not isinstance(rule, SuiteRule):
        raise TypeError(type(rule).__name__)
    return rule


def _regression(**extra: object) -> dict[str, object]:
    return {"input": _QUESTION, "expect": _EXPECT, "tags": ["regression"], **_PAIR, **extra}


class _Raises(Evaluator):
    id = "contains"
    deterministic: ClassVar[bool] = True
    judge_calls_per_verdict: ClassVar[int] = 0

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise RuntimeError("the evaluator broke")


class _Undeclared(Evaluator):
    id = "contains"
    deterministic: ClassVar[bool] = True

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        return Verdict("pass", 1.0, "ok", self.id)


_CONTAINS: Mapping[str, Evaluator] = {"contains": ContainsEvaluator()}


@pytest.mark.parametrize(
    ("case", "overrides", "refusal"),
    [
        (_regression(), {"sample": {"size": 1, "seed": 7}}, "'sample' would leave cases unsent"),
        (_regression(), {"gate": {"min_pass_rate": 0.9, "min_sample": 1}}, "outvote"),
        (
            {"input": _QUESTION, "expect": _EXPECT, **_PAIR},
            {"gate": {"min_pass_rate": 0.5, "min_sample": 1}},
            "outvote",
        ),
    ],
)
def test_a_regression_dataset_refuses_a_suite_that_samples_or_tolerates_a_failure(
    tmp_path: Path, case: dict[str, object], overrides: dict[str, object], refusal: str
) -> None:
    path = _suite(tmp_path, [case, {"input": "Where is my invoice?"}], **overrides)

    with pytest.raises(RuleLoadError, match=refusal):
        load_yaml_rules(path)


def test_the_same_suite_without_a_regression_case_may_sample_and_tolerate(
    tmp_path: Path,
) -> None:
    path = _suite(
        tmp_path,
        [{"input": _QUESTION, "expect": _EXPECT}, {"input": "Where is my invoice?"}],
        sample={"size": 1, "seed": 7},
        gate={"min_pass_rate": 0.5, "min_sample": 1},
    )

    assert _load(path).sample == (1, 7)


@pytest.mark.parametrize("dataset_format", [1, 2])
@pytest.mark.parametrize(
    "overrides",
    [{"gate": {"min_pass_rate": 0.9, "min_sample": 1}}, {"sample": {"size": 1, "seed": 7}}],
)
def test_a_hand_written_regression_tag_without_a_pair_keeps_its_suite_loading(
    tmp_path: Path, dataset_format: int, overrides: dict[str, object]
) -> None:
    path = _suite(
        tmp_path,
        [
            {"input": _QUESTION, "expect": _EXPECT, "tags": ["regression"]},
            {"input": "Where is my invoice?"},
        ],
        **overrides,
    )
    dataset = tmp_path / "support.jsonl"
    header, *cases = dataset.read_text("utf-8").splitlines()
    rewritten = json.dumps({**json.loads(header), "guardana_dataset": dataset_format})
    dataset.write_text("\n".join([rewritten, *cases]) + "\n", encoding="utf-8")

    assert _load(path).regression_cases == ()


def test_a_regression_suite_at_a_bar_of_one_loads_with_its_pair(tmp_path: Path) -> None:
    rule = _load(_suite(tmp_path, [_regression()]))

    (case,) = rule.regression_cases
    assert case.pair == RegressionPair(observed=_BAD, accepted=_GOOD)
    assert case.line == 2


def test_a_live_run_sends_only_the_input_and_grades_the_targets_reply(tmp_path: Path) -> None:
    rule = _load(_suite(tmp_path, [_regression()]))
    registry = Registry()
    registry.register_rule(rule)
    registry.register_evaluator(ContainsEvaluator())
    transport = ScriptedTransport(_BAD)
    runner = Runner(registry=registry, profile=Profile("t", Policy()), calibrations={})

    result = runner.run(EndpointTarget("http://model.test", "m", transport=transport))

    assert [[m.content for m in seen] for seen in transport.seen] == [[_QUESTION]]
    assert result.suites["acme.quality.support"].outcome is SuiteOutcome.FAIL


def test_a_case_identity_leaves_its_pair_out(tmp_path: Path) -> None:
    paired = _load(_suite(tmp_path / "a", [_regression()]))
    unpaired = _load(_suite(tmp_path / "b", [{"input": _QUESTION, "expect": _EXPECT}]))

    assert paired.cases[0].case_id == unpaired.cases[0].case_id


def _proof(evaluator: Evaluator, observed: str, accepted: str) -> tuple[Graded, Graded]:
    proof = prove(
        evaluator,
        (ChatMessage(role="user", content=_QUESTION),),
        Expectation(fields=_EXPECT),
        RegressionPair(observed=observed, accepted=accepted),
    )
    return proof.observed.graded, proof.accepted.graded


def test_a_pair_holds_only_when_the_failure_fails_and_the_correct_reply_passes() -> None:
    proof = prove(
        ContainsEvaluator(),
        (ChatMessage(role="user", content=_QUESTION),),
        Expectation(fields=_EXPECT),
        RegressionPair(observed=_BAD, accepted=_GOOD),
    )

    assert (proof.observed.graded, proof.accepted.graded) == (Graded.FAIL, Graded.PASS)
    assert proof.holds
    assert proof.breach is None


@pytest.mark.parametrize(
    ("observed", "accepted", "graded", "breach"),
    [
        (_GOOD, _GOOD, (Graded.PASS, Graded.PASS), Breach.WRONG_WAY),
        (_BAD, _BAD, (Graded.FAIL, Graded.FAIL), Breach.WRONG_WAY),
        (_GOOD, _BAD, (Graded.PASS, Graded.FAIL), Breach.WRONG_WAY),
        (_BAD, "", (Graded.FAIL, Graded.DECLINED), Breach.DECLINED),
        (_GOOD, "", (Graded.PASS, Graded.DECLINED), Breach.WRONG_WAY),
    ],
)
def test_a_pair_that_does_not_separate_names_what_each_side_did(
    observed: str, accepted: str, graded: tuple[Graded, Graded], breach: Breach
) -> None:
    proof = prove(
        ContainsEvaluator(),
        (ChatMessage(role="user", content=_QUESTION),),
        Expectation(fields=_EXPECT),
        RegressionPair(observed=observed, accepted=accepted),
    )

    assert (proof.observed.graded, proof.accepted.graded) == graded
    assert not proof.holds
    assert proof.breach is breach
    assert proof.describe() == f"observed graded {graded[0]}, accepted graded {graded[1]}"


def test_an_evaluator_that_raises_is_a_side_that_raised_never_a_verdict() -> None:
    assert _proof(_Raises(), _BAD, _GOOD) == (Graded.RAISED, Graded.RAISED)


@pytest.mark.parametrize(
    ("evaluator", "reason"),
    [
        (None, "not registered"),
        (KeywordEvaluator(), "deterministic"),
        (_Undeclared(), "asks no judge"),
    ],
)
def test_only_a_declared_deterministic_evaluator_that_asks_no_judge_can_prove(
    evaluator: Evaluator | None, reason: str
) -> None:
    assert reason in (unprovable_reason("x", evaluator) or "")
    assert unprovable_reason("contains", ContainsEvaluator()) is None


def test_regrading_a_suite_whose_evaluator_cannot_prove_raises_rather_than_skips(
    tmp_path: Path,
) -> None:
    rule = _load(_suite(tmp_path, [_regression()]))

    with pytest.raises(UnprovableError, match="cannot be regraded without sending"):
        regrade(rule, {"contains": _Undeclared()})
    assert broken_pairs([rule], {}) != ()


def test_a_suite_without_a_pair_needs_no_provable_evaluator(tmp_path: Path) -> None:
    rule = _load(_suite(tmp_path, [{"input": _QUESTION, "expect": _EXPECT}]))

    assert regrade(rule, {}) == ()
    assert broken_pairs([rule], {}) == ()


def test_broken_pairs_names_the_rule_and_dataset_line_of_each_one(tmp_path: Path) -> None:
    rule = _load(
        _suite(
            tmp_path,
            [_regression(), _regression(input="Where is my invoice?", observed=_GOOD)],
        )
    )

    assert broken_pairs([rule], _CONTAINS) == (
        "acme.quality.support dataset line 3: observed graded pass, accepted graded pass",
    )


def test_verification_regrades_every_pair_and_is_not_proven_over_a_broken_one(
    tmp_path: Path,
) -> None:
    fixtures = [
        {"name": "answers", "reply": _GOOD, "outcome": "clean"},
        {"name": "refuses", "reply": _BAD, "outcome": "finding"},
        {"name": "silent", "reply": "", "outcome": "inconclusive"},
    ]
    holding = _load(_suite(tmp_path / "a", [_regression()], fixtures=fixtures))
    broken = _load(_suite(tmp_path / "b", [_regression(observed=_GOOD)], fixtures=fixtures))
    ctx = RuleContext(evaluators=dict(_CONTAINS))

    proven = verify_rule(holding, ctx)
    failed = verify_rule(broken, ctx)
    refused = verify_rule(holding, RuleContext(evaluators={"contains": KeywordEvaluator()}))

    assert proven.is_proven, proven
    assert [r.line for r in proven.regressions] == [2]
    assert not failed.is_proven
    assert [r.line for r in failed.wrong_way] == [2]
    assert not refused.is_proven
    assert refused.unprovable is not None


@pytest.fixture(autouse=True)
def _directories(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
