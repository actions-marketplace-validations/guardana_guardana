from collections.abc import Mapping
from typing import ClassVar

from guardana.core.evaluator._turns import first_matching, which_turn
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange

_LISTS = ("contains_all", "contains_any", "contains_none")


class ContainsEvaluator(Evaluator):
    """Grades a reply by the substrings it carries, case-sensitively.

    Passes when every `contains_all` entry is present, at least one `contains_any`
    entry is present (when that list is given), and no `contains_none` entry is.
    With every list absent or empty there is nothing to look for, and a check that
    has not looked is `inconclusive`, never a pass. Confidence 1.0: a substring is
    either there or not.

    `contains_all` and `contains_any` describe the answer, so they read the final
    reply. `contains_none` names what must never be said, so it reads every reply
    under grade: an agent run that said it in step one and ended cleanly still said it.
    """

    id = "contains"
    deterministic: ClassVar[bool] = True
    judge_calls_per_verdict: ClassVar[int] = 0
    expects: ClassVar[Mapping[str, bool]] = dict.fromkeys(_LISTS, False)

    @classmethod
    def check_fields(cls, expectation: Expectation) -> str | None:
        """Return why a list is not a list of non-empty strings, or None."""
        for name in _LISTS:
            raw = expectation.get(name)
            if raw is None:
                continue
            if not isinstance(raw, list) or not all(isinstance(s, str) and s for s in raw):
                return f"evaluator {cls.id!r}: 'expect.{name}' must be a list of non-empty strings"
        return None

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Pass when the reply carries what it must and none of what it must not."""
        problem = self.check_fields(expectation)
        if problem is not None:
            return Verdict("inconclusive", 0.0, problem, self.id)
        every, some, none_of = (_strings(expectation.get(name)) for name in _LISTS)
        if not (every or some or none_of):
            return Verdict(
                "inconclusive",
                0.0,
                "nothing to look for: contains_all, contains_any and contains_none are all empty",
                self.id,
            )
        reply = exchange.reply_text
        if reply is not None:
            why = _why_not(reply, every, some, none_of)
            if why is not None:
                return Verdict("fail", 1.0, why, self.id)
        replies = exchange.graded_replies
        said = first_matching(replies, lambda text: any(s in text for s in none_of))
        if said is not None:
            forbidden = next(s for s in none_of if s in replies[said - 1])
            where = which_turn(said, len(replies), alone="reply")
            return Verdict("fail", 1.0, f"{where} carries {forbidden!r}.", self.id)
        if reply is None:
            return Verdict("inconclusive", 0.0, "No model reply to search.", self.id)
        return Verdict("pass", 1.0, "reply carries what it must and nothing it must not.", self.id)


def _why_not(reply: str, every: list[str], some: list[str], none_of: list[str]) -> str | None:
    missing = [s for s in every if s not in reply]
    if missing:
        return f"reply lacks {missing[0]!r}."
    if some and not any(s in reply for s in some):
        return "reply carries none of contains_any."
    forbidden = [s for s in none_of if s in reply]
    if forbidden:
        return f"reply carries {forbidden[0]!r}."
    return None


def _strings(raw: object) -> list[str]:
    return [s for s in raw if isinstance(s, str)] if isinstance(raw, list) else []
