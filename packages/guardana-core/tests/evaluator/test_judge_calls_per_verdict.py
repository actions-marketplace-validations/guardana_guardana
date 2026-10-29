"""Every built-in evaluator says what one verdict costs, and the judges' numbers hold.

`guardana plan probe` multiplies these numbers by the verdicts a rule grades. A
built-in left at the base default would be priced as unknown, and one declaring
fewer calls than it makes would let a plan claim to fit a budget the run exceeds.
"""

import importlib
import inspect
import pkgutil
from collections.abc import Iterator

import guardana.core.evaluator as evaluator_package
import pytest
from guardana.core.evaluator import CONFIG_WIRED, Evaluator, Expectation, Verdict
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.exchange import Exchange
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry


def _built_in_classes() -> Iterator[type[Evaluator]]:
    """Every concrete evaluator class defined anywhere under `guardana.core.evaluator`."""
    for info in pkgutil.iter_modules(evaluator_package.__path__):
        module = importlib.import_module(f"{evaluator_package.__name__}.{info.name}")
        for _name, cls in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(cls, Evaluator)
                and cls.__module__ == module.__name__
                and not inspect.isabstract(cls)
            ):
                yield cls


class _Counting:
    """A judge that answers PASS and counts how often it was asked."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, prompt: str) -> str:
        self.calls += 1
        return "PASS: fine"


class _Silent(Evaluator):
    id = "acme.silent"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        return Verdict("pass", 0.5, "never asked anything", self.id)


def test_every_built_in_evaluator_class_declares_its_calls_itself() -> None:
    classes = list(_built_in_classes())
    assert len(classes) >= len(CONFIG_WIRED) + 10, "the scan found too few evaluators to mean it"

    undeclared = [c.__name__ for c in classes if "judge_calls_per_verdict" not in vars(c)]

    assert not undeclared, f"these evaluators inherit an unknown judge cost: {undeclared}"


def test_every_evaluator_the_registry_discovers_answers_an_explicit_count() -> None:
    discovered = {
        evaluator_id: evaluator
        for evaluator_id, evaluator in Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
        .evaluators()
        .items()
        if type(evaluator).__module__.startswith("guardana.")
    }
    assert "canary" in discovered, "discovery found no built-in evaluator to check"

    for evaluator_id, evaluator in discovered.items():
        calls = evaluator.judge_calls_per_verdict
        assert type(calls) is int, f"{evaluator_id} declares {calls!r}"


def test_an_evaluator_that_declares_nothing_is_of_unknown_cost() -> None:
    assert _Silent().judge_calls_per_verdict is None


@pytest.mark.parametrize("samples", [1, 3])
def test_a_judge_asks_exactly_its_declared_calls_for_one_verdict(samples: int) -> None:
    llm, reference = _Counting(), _Counting()
    exchange = Exchange.single_reply("The answer is 42.")
    judges: list[tuple[Evaluator, _Counting, Expectation]] = [
        (LlmJudgeEvaluator(llm, min_agreement=samples), llm, Expectation(goal="g")),
        (
            ReferenceJudgeEvaluator(reference, min_agreement=samples),
            reference,
            Expectation(fields={"reference": "42"}),
        ),
    ]

    for evaluator, judge, expectation in judges:
        evaluator.evaluate(exchange, expectation)
        assert judge.calls == evaluator.judge_calls_per_verdict == samples, evaluator.id


def test_a_guard_asks_once_per_verdict() -> None:
    guard = _Counting()
    evaluator = GuardEvaluator(guard)

    evaluator.evaluate(Exchange.single_reply("hello"), Expectation())

    assert guard.calls == evaluator.judge_calls_per_verdict == 1
