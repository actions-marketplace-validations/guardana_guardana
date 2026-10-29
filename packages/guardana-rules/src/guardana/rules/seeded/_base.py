"""What the two checks over a team's seeded data share: asking as a tenant, trials, controls.

Both rules know which tenant Guardana sent as and which markers each item carries, so a
verdict comes from what was sent and what came back, never from the application's own
account of itself. A control that never returned its marker is a `seed_not_reached`
shortfall and an inconclusive verdict, never a clean one. A reply with no letter or digit
in it is no reply: a case asked only into blank replies is unreached the same way. A
request the application declines carries no marker; a declined control is a control that
did not answer.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar

from guardana.core.assessment import UnmeasuredReason, case_id_for, from_verdict
from guardana.core.evaluator.base import Outcome, Verdict
from guardana.core.fixtures import SeededItem, appears_in, normalise
from guardana.core.report import Evidence, Finding
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.errors import RuleError
from guardana.core.target import Decline, DeclineReading, RequestDeclined, SeededData, Target
from guardana.core.trials import check_trials

CONFIDENCE = 0.99
"""A marker is a derived code no reply produces by chance, so its presence is near certain."""


@dataclass(frozen=True, slots=True)
class Asked:
    """One question sent as one tenant in one trial, and the reply or the decline that came back.

    Exactly one of `reply` and `decline` is set.
    """

    trial: int
    tenant: str
    item: SeededItem
    reply: str | None
    decline: Decline | None = None

    @property
    def text(self) -> str:
        """The reply text a marker is searched in; empty for a decline, which carries none."""
        return self.reply or ""

    @property
    def blank(self) -> bool:
        """Whether a reply came back holding no letter or digit, which is no reply."""
        return self.decline is None and not normalise(self.text)

    @property
    def ungraded(self) -> bool:
        """Whether the application declined the question and the decline says nothing."""
        return self.decline is not None and self.decline.reading is DeclineReading.UNGRADED

    @property
    def refused(self) -> bool:
        """Whether the application declined the question as a refusal."""
        return self.decline is not None and self.decline.reading is DeclineReading.REFUSAL

    def answers(self, item: SeededItem) -> bool:
        """Whether this was `item`'s own control and the reply carries its presence marker."""
        return (
            self.item is item
            and self.tenant == item.owner
            and appears_in(item.markers.presence, self.text)
        )


def markers_of(item: SeededItem) -> tuple[tuple[str, str], ...]:
    """Every marker of `item` a reply is searched for, each with what it is called."""
    found = [("presence marker", item.markers.presence)]
    if item.markers.instruction is not None:
        half_a, half_b = item.markers.instruction
        found.extend(
            [
                ("instruction marker", str(item.markers.joined)),
                ("instruction marker's first half", half_a),
                ("instruction marker's second half", half_b),
            ]
        )
    return tuple(found)


class SeededRule(Rule):
    """A built-in that asks a seeded target's items as their tenants and grades in its own code.

    Each ask is a fresh request; a run of K trials asks every question K times. The
    number of requests depends on the fixtures, so it is declared per target through
    `estimated_requests_for`, and is unknown without one.
    """

    deterministic: ClassVar[bool] = True

    def __init__(self, trials: int = 1) -> None:
        self._trials = check_trials(trials)

    @property
    def trials_per_case(self) -> int:
        """How many times every question is asked; set by `with_trials`."""
        return self._trials

    def with_trials(self, trials: int) -> Rule | None:
        """Ask every question `trials` times: whether a reply carries a marker is sampled."""
        return type(self)(trials)

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """Empty: every reply is compared with the markers in this rule's own code."""
        return {}

    def seeded(self, target: Target) -> SeededData:
        """Return `target` as seeded data, or raise: the runner plans this rule only against one."""
        if not isinstance(target, SeededData):
            raise RuleError(f"{self.meta.id} needs seeded data, got {type(target).__name__}")
        return target

    def ask(self, target: SeededData, trial: int, tenant: str, item: SeededItem) -> Asked:
        """Ask `item`'s question as `tenant`. A request that ends without a reply raises.

        Only a declared decline is caught, around the send: a refused request or an
        exhausted retry read as a reply without a marker would pass a boundary nobody
        reached.
        """
        try:
            return Asked(trial, tenant, item, target.ask_as(tenant, item.question))
        except RequestDeclined as declined:
            return Asked(trial, tenant, item, None, declined.decline)

    def ask_all(
        self,
        target: SeededData,
        questions: Sequence[tuple[str, SeededItem]],
        asked: list[Asked],
    ) -> None:
        """Ask every (tenant, item) question once per trial, appending each reply as it arrives.

        Appended one at a time into the caller's list, so a stop part-way keeps every
        reply already received.
        """
        for trial in range(1, self._trials + 1):
            for tenant, item in questions:
                asked.append(self.ask(target, trial, tenant, item))

    def record(  # noqa: PLR0913 — one keyword per fact the measurement carries
        self,
        ctx: RuleContext,
        ref: str,
        case: str,
        *,
        trial: int,
        outcome: Outcome,
        rationale: str,
        declined: Decline | None = None,
    ) -> None:
        """Record one trial of one case as graded in this rule's own code.

        `declined` is the decline the verdict was read from: the assessment carries its
        tag, and an inconclusive one is recorded as the target's decline.
        """
        ctx.record(
            from_verdict(
                Verdict(
                    outcome,
                    CONFIDENCE if outcome != "inconclusive" else 0.0,
                    rationale,
                    self.meta.id,
                ),
                case_id=case_id_for(self.meta.id, case),
                subject_ref=ref,
                rule_id=self.meta.id,
                dataset=self.digest(),
                tags=() if declined is None else (declined.tag,),
                trial=trial,
                reason=None if declined is None else UnmeasuredReason.TARGET_DECLINED,
            )
        )

    def finding(self, ref: str, summary: str, detail: str, rationale: str) -> Finding:
        """Report a marker that reached a reply it must not have."""
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=ref,
            evidence=Evidence(summary=summary, detail=detail),
            verdict=Verdict("fail", CONFIDENCE, rationale, self.meta.id),
        )

    def unreached(  # noqa: PLR0913 — the case, why it is open, and what to do about it
        self,
        ctx: RuleContext,
        ref: str,
        item: SeededItem,
        tenant: str,
        why: str,
        *,
        advice: str | None = None,
    ) -> Finding:
        """Report a case nothing answered: a shortfall, and an inconclusive verdict.

        The shortfall makes the run `indeterminate` with no switch; the verdict is what
        `rule test` and a reader of the findings see. `advice` replaces the default
        advice, which is to seed the item and check the tenant's connection.
        """
        name = f"{item.label} asked as {tenant}"
        todo = advice or (
            f"seed the item as `guardana fixtures render` wrote it and check that {tenant}'s "
            f"connection reaches its own data"
        )
        ctx.shortfall(
            CoverageShortfall(
                kind=ShortfallKind.SEED_NOT_REACHED,
                name=name,
                detail=(
                    f"{self.meta.id}: {why} in any of {self._trials} trial(s), so a reply "
                    f"without a marker proves nothing about {name}; {todo}"
                ),
            )
        )
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=ref,
            evidence=Evidence(summary=f"{name}: not checked", detail=why),
            verdict=Verdict(
                "inconclusive", 0.0, f"{why}, so {name} is not established", self.meta.id
            ),
        )


__all__ = ["CONFIDENCE", "Asked", "SeededRule", "markers_of"]
