"""Prove a regression case on both sides: its failure still fails and a correct reply passes.

A case's expectation gates something only while it tells the failure it was promoted from
apart from a correct reply. The proof grades both replies with the suite's own evaluator
and the case's effective expectation, sending nothing, so only an evaluator that declares
itself deterministic and asks no judge can give it.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from guardana.core.dataset import RegressionPair
from guardana.core.evaluator.base import Evaluator, Expectation, grade
from guardana.core.exchange import Exchange
from guardana.core.rule.suite_rule import SuiteCase, SuiteRule
from guardana.core.target import ChatMessage


class Graded(StrEnum):
    """How one side of a pair came out."""

    PASS = "pass"  # noqa: S105 — a verdict, not a credential
    FAIL = "fail"
    DECLINED = "declined"
    """The evaluator returned `inconclusive`."""

    RAISED = "raised"
    """The evaluator raised instead of returning a verdict."""


@dataclass(frozen=True, slots=True)
class Side:
    """One reply's grade, and the evaluator's reason, which may quote the reply."""

    graded: Graded
    reason: str


class Breach(StrEnum):
    """Why a pair does not hold, from the most actionable to the least."""

    WRONG_WAY = "wrong_way"
    """A side reached the verdict opposite to the one it must: the expectation does not separate."""

    DECLINED = "declined"
    """No side graded the wrong way, and a side declined."""

    RAISED = "raised"
    """No side graded the wrong way or declined, and the evaluator raised on a side."""


@dataclass(frozen=True, slots=True)
class PairProof:
    """Both sides of one pair, graded with one expectation."""

    observed: Side
    accepted: Side

    @property
    def holds(self) -> bool:
        """Whether the failure fails and the correct reply passes; anything else gates nothing."""
        return self.observed.graded is Graded.FAIL and self.accepted.graded is Graded.PASS

    @property
    def breach(self) -> Breach | None:
        """Why the pair does not hold, None when it does.

        A side graded the wrong way outranks a side that declined, which outranks one
        that raised: a wrong verdict is a fact about the expectation, the other two are
        questions the evaluator did not answer.
        """
        if self.holds:
            return None
        sides = (self.observed.graded, self.accepted.graded)
        if self.observed.graded is Graded.PASS or self.accepted.graded is Graded.FAIL:
            return Breach.WRONG_WAY
        if Graded.DECLINED in sides:
            return Breach.DECLINED
        return Breach.RAISED

    def describe(self) -> str:
        """Name what each side did, without quoting either reply."""
        return f"observed graded {self.observed.graded}, accepted graded {self.accepted.graded}"


class UnprovableError(ValueError):
    """An evaluator that cannot prove a pair without sending anything."""


def unprovable_reason(evaluator_id: str, evaluator: Evaluator | None) -> str | None:
    """Return why `evaluator` cannot prove a pair offline, or None when it can.

    Only an evaluator that declares `deterministic` and declares that a verdict asks no
    judge can; one that declares neither is treated as a judge.
    """
    if evaluator is None:
        return f"evaluator {evaluator_id!r} is not registered"
    if evaluator.deterministic is not True:
        return (
            f"evaluator {evaluator_id!r} does not declare itself deterministic, so a verdict "
            f"on a pair would be an opinion, not a fact"
        )
    if evaluator.judge_calls_per_verdict != 0:
        return (
            f"evaluator {evaluator_id!r} does not declare that a verdict asks no judge, and "
            f"proving a pair sends nothing"
        )
    return None


def prove(
    evaluator: Evaluator,
    messages: Sequence[ChatMessage],
    expectation: Expectation,
    pair: RegressionPair,
) -> PairProof:
    """Grade both replies of `pair` to `messages` against `expectation`.

    The caller has checked `unprovable_reason`; an evaluator that raises on a side is
    recorded as having raised there, never as a verdict.
    """
    return PairProof(
        observed=_side(evaluator, messages, expectation, pair.observed),
        accepted=_side(evaluator, messages, expectation, pair.accepted),
    )


def _side(
    evaluator: Evaluator, messages: Sequence[ChatMessage], expectation: Expectation, reply: str
) -> Side:
    exchange = Exchange(
        (*messages, ChatMessage(role="assistant", content=reply)), graded_from=len(messages)
    )
    try:
        verdict = grade(evaluator, exchange, expectation)
    except Exception as exc:  # a third-party evaluator; its failure is a side that raised
        return Side(Graded.RAISED, f"{type(exc).__name__}: {exc}")
    if verdict.outcome == "pass":
        return Side(Graded.PASS, verdict.rationale)
    if verdict.outcome == "fail":
        return Side(Graded.FAIL, verdict.rationale)
    return Side(Graded.DECLINED, verdict.rationale)


@dataclass(frozen=True, slots=True)
class Regraded:
    """One regression case of a suite, regraded with the suite as it is now."""

    rule_id: str
    line: int
    case_id: str
    proof: PairProof

    def describe(self) -> str:
        """Name the case by rule and dataset line and say what each side did."""
        return f"{self.rule_id} dataset line {self.line}: {self.proof.describe()}"


def regrade(rule: SuiteRule, evaluators: Mapping[str, Evaluator]) -> tuple[Regraded, ...]:
    """Regrade every pair of `rule` with its evaluator, raising `UnprovableError` if it cannot.

    A suite with no pair regrades nothing and needs no provable evaluator.
    """
    cases = rule.regression_cases
    if not cases:
        return ()
    evaluator_id = rule.meta.evaluator or ""
    evaluator = evaluators.get(evaluator_id)
    reason = unprovable_reason(evaluator_id, evaluator)
    if reason is not None or evaluator is None:
        raise UnprovableError(
            f"{rule.meta.id} holds {len(cases)} regression case(s) and {reason}; its pairs "
            f"cannot be regraded without sending"
        )
    return tuple(_regraded(rule.meta.id, evaluator, case) for case in cases)


def _regraded(rule_id: str, evaluator: Evaluator, case: SuiteCase) -> Regraded:
    if case.pair is None:
        raise ValueError("only a case carrying a pair is regraded")
    proof = prove(evaluator, case.messages, case.expectation, case.pair)
    return Regraded(rule_id=rule_id, line=case.line, case_id=case.case_id, proof=proof)


def broken_pairs(
    rules: Iterable[SuiteRule], evaluators: Mapping[str, Evaluator]
) -> tuple[str, ...]:
    """Describe every pair of `rules` that no longer holds, and every suite that cannot say.

    Empty only when every pair of every suite was regraded and holds.
    """
    broken: list[str] = []
    for rule in rules:
        try:
            regraded = regrade(rule, evaluators)
        except UnprovableError as exc:
            broken.append(str(exc))
            continue
        broken.extend(r.describe() for r in regraded if not r.proof.holds)
    return tuple(broken)


__all__ = [
    "Breach",
    "Graded",
    "PairProof",
    "Regraded",
    "Side",
    "UnprovableError",
    "broken_pairs",
    "prove",
    "regrade",
    "unprovable_reason",
]
