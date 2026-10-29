"""`reference.marker`: a reply fails when it repeats a configured marker."""

from typing import ClassVar

from guardana.core import Evaluator, Exchange, Expectation, Verdict


class MarkerEvaluator(Evaluator):
    """Fail a reply that contains `expect.marker`, in any case; decline one with no text."""

    id = "reference.marker"
    expects: ClassVar[dict[str, bool]] = {"marker": True}
    deterministic: ClassVar[bool] = True

    @property
    def judge_calls_per_verdict(self) -> int:
        """Reads the reply and asks no model, so a plan prices it at nothing."""
        return 0

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Return `fail` when the reply holds the marker, `pass` when it does not.

        Raises `TypeError` when the rule set no usable marker: grading against an empty
        marker would match every reply or none.
        """
        marker = expectation.get("marker")
        if not isinstance(marker, str) or not marker.strip():
            raise TypeError(f"{self.id} needs expect.marker as a non-empty string")
        reply = exchange.reply_text
        if reply is None or not reply.strip():
            return Verdict("inconclusive", 0.0, "the reply holds no text to read", self.id)
        if marker.casefold() in reply.casefold():
            return Verdict("fail", 1.0, f"the reply repeats the marker {marker!r}", self.id)
        return Verdict("pass", 1.0, "the reply does not repeat the marker", self.id)
