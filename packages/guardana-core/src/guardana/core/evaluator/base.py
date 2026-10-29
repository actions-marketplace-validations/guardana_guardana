import math
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import ClassVar, Literal

from guardana.core.assessment import Direction
from guardana.core.exchange import Exchange
from guardana.core.target.decline import DeclineReading

Outcome = Literal["pass", "fail", "inconclusive"]


@dataclass(frozen=True, slots=True)
class Expectation:
    """What a robust model would have done — the yardstick an evaluator grades against.

    `canary` and `goal` are typed because the engine itself handles them: the probe
    plants the canary, and every grading path can render a goal. Anything else an
    evaluator needs lives in `fields`, the same open door a third-party evaluator
    uses — so a built-in and a plugin declare their inputs the same way.
    """

    canary: str | None = None
    goal: str | None = None
    fields: Mapping[str, object] = field(default_factory=dict)

    def get(self, name: str, default: object = None) -> object:
        """Read one evaluator-specific field, falling back to `default`."""
        return self.fields.get(name, default)


def check_expectation(
    evaluator_id: str, expects: Mapping[str, bool], expectation: Expectation
) -> str | None:
    """Return why `expectation` does not satisfy an evaluator's contract, or None.

    Two failures, both of which would otherwise produce a rule that looks
    configured and grades nothing: a required field the rule never set, and a
    field name the evaluator does not know — the `promts:` typo one level down.
    """
    for name, required in expects.items():
        if required and expectation.get(name) is None and _typed(expectation, name) is None:
            return f"evaluator {evaluator_id!r} requires 'expect.{name}'"
    unknown = sorted(set(expectation.fields) - set(expects))
    if unknown:
        return (
            f"evaluator {evaluator_id!r} does not use expect field(s): {', '.join(unknown)}; "
            f"it reads {', '.join(sorted(expects)) or 'none'}"
        )
    return None


def check_judge_identity(identity: str | None) -> str | None:
    """Return `identity` unchanged, refusing a blank one.

    Identities are compared verbatim, so two blank ones would match two different
    judges; a judge with nothing to state passes None.
    """
    if identity is not None and not identity.strip():
        raise ValueError("judge_identity must be None or a non-blank string")
    return identity


def _typed(expectation: Expectation, name: str) -> object | None:
    return {"canary": expectation.canary, "goal": expectation.goal}.get(name)


@dataclass(frozen=True, slots=True)
class Measurement:
    """The number behind a verdict, what it is counted in, and which way is better.

    `threshold` is the bound the verdict was decided against in this run. Two runs
    whose unit, direction or threshold differ answered different questions, so a
    comparison refuses to pair them.
    """

    value: float
    unit: str
    direction: Direction
    threshold: float | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.value):
            raise ValueError(f"a measurement's value must be finite, got {self.value}")
        if self.threshold is not None and not math.isfinite(self.threshold):
            raise ValueError(f"a measurement's threshold must be finite, got {self.threshold}")
        if not isinstance(self.unit, str) or not self.unit.strip():
            raise ValueError("a measurement's unit must be a non-blank string")
        if not isinstance(self.direction, Direction):
            raise TypeError(
                f"a measurement's direction must be a Direction, got {self.direction!r}"
            )


@dataclass(frozen=True, slots=True)
class Verdict:
    """An evaluator's judgement, with the confidence that makes it actionable.

    `confidence` is what lets a policy gate on "only fail CI on findings we're
    sure about" — a dynamic finding without it is unusable in CI. `measurement`
    is the number the verdict was read from, for an evaluator that has one.
    """

    outcome: Outcome
    confidence: float
    rationale: str
    evaluator_id: str
    measurement: Measurement | None = None

    def __post_init__(self) -> None:
        # Evaluators are third-party plugins; an out-of-range confidence would
        # silently distort policy gate thresholds, so the contract is enforced.
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be within [0.0, 1.0], got {self.confidence} "
                f"(evaluator {self.evaluator_id!r})"
            )


class Evaluator(ABC):
    """Decides whether an exchange is a finding, with a confidence."""

    id: str

    expects: ClassVar[Mapping[str, bool]] = {}
    """The `expect:` fields this evaluator reads, mapped to whether each is required.

    Declaring them is what lets a YAML author configure a third-party evaluator at
    all: the loader accepts exactly these keys for this evaluator and rejects the
    rest, so `expect: {canry: ...}` fails loudly instead of producing a rule that
    grades nothing. An evaluator that needs no configuration leaves it empty.
    """

    deterministic: ClassVar[bool] = False
    """Whether a verdict is a fact read off the exchange rather than an opinion about it.

    A deterministic evaluator (a planted canary found verbatim, the tools a run
    called) has no error rate to correct. Anything else is a judge: a rate it graded
    is corrected with its measured sensitivity and specificity, or says it is not.
    False unless declared, so an evaluator that says nothing is treated as a judge.
    """

    judge_identity: str | None = None
    """Everything behind a verdict that the evaluator id does not name, or None.

    For a judge backed by a model: which model, where it is served, how many samples
    make one verdict. A calibration measured under one identity says nothing about
    another, so the two are compared verbatim. None when the evaluator states none.
    """

    @property
    def assessor_id(self) -> str:
        """The `evaluator_id` this evaluator's verdicts carry, known before any verdict exists.

        `id` by default. An evaluator whose verdicts name something more (a versioned
        rubric) overrides it, so a trial nobody could grade is attributed to the same
        assessor as the trials it did grade.
        """
        return self.id

    @property
    def judge_calls_per_verdict(self) -> int | None:
        """At most how many judge or model calls one `evaluate` makes, or None if unknown.

        What `guardana plan probe` multiplies by the verdicts a rule grades to price
        judge calls against a request budget. None here: the engine never claims zero
        cost for code it has not read, so an evaluator that does not declare it is
        listed as of unknown cost. Not inferred from `deterministic`, which is about
        whether a verdict is a fact, not about whether grading it calls anything.
        """
        return None

    @abstractmethod
    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Grade one exchange against one expectation.

        Be honest about `confidence`: a cheap heuristic that reports 0.99 is worse
        than one that reports 0.5, because a policy trusts the number. When the
        exchange has no reply to grade (`reply_text is None`), return
        `inconclusive`, never `pass`. Every built-in rule kind grades through `grade`,
        which turns a `pass` on an exchange with no reply text and no agent run into
        `inconclusive`; a `fail` stands. A Python rule that asks an evaluator calls it too.
        """
        raise NotImplementedError

    def read_decline(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Grade a request the application declined as a refusal (`exchange.decline`).

        `inconclusive` here: an evaluator that grades reply text has none to grade, so a
        decline never passes through an evaluator that did not say what a refusal means
        for it. Override it to say so; `grade` calls it only for a decline read as a
        refusal, and only after any earlier replies under grade did not fail.
        """
        return Verdict(
            "inconclusive",
            0.0,
            f"{_declined(exchange)}; {self.id} grades reply text, and a declined request has none",
            self.assessor_id,
        )


def grade(evaluator: Evaluator, exchange: Exchange, expectation: Expectation) -> Verdict:
    """Ask `evaluator` for a verdict, refusing a `pass` on an exchange with nothing to grade.

    Evaluators are third-party plugins, and one that only looks for something bad finds
    nothing bad in an empty reply. An agent run is exempt: a grader of its tool calls
    may clear a run that ended without final text. A declined exchange is read as
    `grade_decline` reads it.
    """
    return grade_decline(evaluator, exchange, expectation)[0]


def grade_decline(
    evaluator: Evaluator, exchange: Exchange, expectation: Expectation
) -> tuple[Verdict, bool]:
    """Grade `exchange` as `grade` does, and say whether the verdict came from its decline.

    A declined exchange is read in two steps. Replies under grade before the decline (a
    scenario's earlier turns) are graded first, and a `fail` there stands: a leak is not
    taken back by a later decline. Otherwise a decline read as `ungraded` is
    `inconclusive`, and one read as a refusal is what `Evaluator.read_decline` says. The
    flag is True only for a verdict read from the decline, which is what a rule tags and
    what a suite's judge-error correction leaves out.
    """
    decline = exchange.decline
    if decline is None:
        return _checked(evaluator, exchange, expectation), False
    earlier = earlier_failure(evaluator, exchange, expectation)
    if earlier is not None:
        return earlier, False
    if decline.reading is DeclineReading.UNGRADED:
        return Verdict(
            "inconclusive",
            0.0,
            f"{decline.described}, read as ungraded: the request was not answered, and that "
            f"says nothing about the check",
            evaluator.assessor_id,
        ), True
    return evaluator.read_decline(exchange, expectation), True


def earlier_failure(
    evaluator: Evaluator, exchange: Exchange, expectation: Expectation
) -> Verdict | None:
    """Return the `fail` the replies under grade before a decline already show, or None.

    The half of `grade_decline` that never reads the decline itself, so a scope the decline
    kept from being sent can still fail on what was said before it.
    """
    if not exchange.graded_replies:
        return None
    verdict = _checked(evaluator, exchange, expectation)
    return verdict if verdict.outcome == "fail" else None


def _declined(exchange: Exchange) -> str:
    """Name the exchange's decline for a rationale."""
    if exchange.decline is None:
        return "no decline was recorded for this exchange"
    return exchange.decline.described


def _checked(evaluator: Evaluator, exchange: Exchange, expectation: Expectation) -> Verdict:
    """Ask `evaluator` for a verdict, turning a `pass` on nothing to grade into `inconclusive`."""
    verdict = evaluator.evaluate(exchange, expectation)
    if (
        verdict.outcome != "pass"
        or exchange.reply_text is not None
        or exchange.trajectory is not None
    ):
        return verdict
    return replace(
        verdict,
        outcome="inconclusive",
        confidence=0.0,
        rationale=(
            f"no reply to grade: the exchange ended without reply text, so the evaluator's "
            f"pass carries no evidence ({verdict.rationale})"
        ),
        measurement=None,
    )
