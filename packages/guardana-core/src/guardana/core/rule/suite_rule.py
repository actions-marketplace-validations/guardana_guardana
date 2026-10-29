"""A quality suite: every case of a versioned dataset, sent K times, gated on its pass rate.

The fourth declarative shape, picked by `dataset:`. It grades each reply with an ordinary
evaluator, records one assessment per trial with the pass included, and yields at most
one finding, about the rate rather than a case.
"""

import hashlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from functools import cache

from guardana.core.assessment import (
    Assessment,
    AssessmentStatus,
    UnmeasuredReason,
    from_verdict,
)
from guardana.core.budget import BudgetExhausted
from guardana.core.calibration.corpus import bundled_corpus
from guardana.core.calibration.store import corpus_digest
from guardana.core.dataset import RegressionPair
from guardana.core.evaluator.base import Expectation, Verdict, grade_decline
from guardana.core.manifest.records import SuiteOutcome, SuiteSummary
from guardana.core.report import Evidence, Finding
from guardana.core.rule._send import answered, decline_reason, decline_tags, send
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.rule.fixture import DeclaredFixture, RuleFixture, materialise
from guardana.core.suite import SuiteGate, describe, measure_suite
from guardana.core.target import ChatMessage, ReplyUnavailable, Target
from guardana.core.target.protocols import ChatEndpoint
from guardana.core.trials import check_trials

_EVIDENCE_CASES = 3
"""How many failing cases a finding quotes: enough to act on, few enough to read."""


@dataclass(frozen=True, slots=True)
class SuiteCase:
    """One case of a suite, ready to send: its identity, its messages and its yardstick.

    `line` is the case's dataset line, 0 for a case built in code. `pair` is a
    regression case's failing and accepted replies; the run never reads it.
    """

    case_id: str
    messages: tuple[ChatMessage, ...]
    expectation: Expectation
    tags: tuple[str, ...] = ()
    line: int = 0
    pair: RegressionPair | None = None


@dataclass(frozen=True, slots=True)
class SuiteRule(Rule):
    """A dataset of cases sent to a chat endpoint and gated on the share that pass."""

    meta: RuleMeta
    cases: tuple[SuiteCase, ...]
    """The cases this suite sends, after sampling."""

    gate: SuiteGate
    dataset: str
    """The dataset's declared identity, `name@version`, recorded on every assessment."""

    dataset_digest: str
    sample: tuple[int, int] | None = None
    """(size, seed) when a subset of the dataset runs; None when every case does."""

    source_digest: str = ""
    """Hash of the declaration and the dataset file; see `Rule.digest`."""

    declared_fixtures: tuple[RuleFixture | DeclaredFixture, ...] = ()
    trials_per_case: int = 1

    def fixtures(self) -> Iterable[RuleFixture]:
        """Build this suite's samples, each with a fresh double."""
        return materialise(self.declared_fixtures)

    @property
    def regression_cases(self) -> tuple[SuiteCase, ...]:
        """The cases carrying a regression pair, in dataset order."""
        return tuple(case for case in self.cases if case.pair is not None)

    def digest(self) -> str:
        """Return the declaration and dataset hash, falling back to the metadata-only default."""
        return self.source_digest or Rule.digest(self)

    @property
    def estimated_requests(self) -> int:
        """One request per case per trial: every case is sent every time, none is skipped."""
        return len(self.cases) * self.trials_per_case

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """One verdict per case per trial, all from the suite's evaluator."""
        return {self.meta.evaluator or "": len(self.cases) * self.trials_per_case}

    def with_trials(self, trials: int) -> "Rule | None":
        """Send every case `trials` times: a pass rate over one sampled reply is one draw."""
        return replace(self, trials_per_case=check_trials(trials))

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Report every case's expectation, so a third-party evaluator's contract is checked."""
        evaluator = self.meta.evaluator or ""
        return ((evaluator, case.expectation) for case in self.cases)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send each case once per trial, record every grade, and yield the gate's finding.

        Nothing is yielded when the suite passes: the passes are in the assessment
        channel and in the conclusion handed to `ctx.conclude`. A suite that raises
        before it concludes still concludes, as declined, so an error never leaves its
        demand unanswered. A spent budget concludes it declined too, over every planned
        case, and still propagates: the stop is the run's to report.
        """
        # A context can outlive one run (fixtures share one), so the suite reads only what
        # it recorded itself.
        start = len(ctx.recorded())
        try:
            yield from self._measure(target, ctx, start)
        except BudgetExhausted:
            ctx.conclude(self._declined(ctx, start, _stopped_reason))
            raise
        except Exception as exc:
            failure = f"suite did not finish: {type(exc).__name__}: {exc}"
            ctx.conclude(self._declined(ctx, start, lambda _: failure))
            raise

    def _declined(
        self, ctx: RuleContext, start: int, reason: Callable[[SuiteSummary], str]
    ) -> SuiteSummary:
        """Summarise what was recorded over every planned case, declined for `reason`."""
        summary = self._summary(ctx, ctx.recorded()[start:])
        return replace(summary, outcome=SuiteOutcome.INCONCLUSIVE, reason=reason(summary))

    def _summary(self, ctx: RuleContext, recorded: Sequence[Assessment]) -> SuiteSummary:
        return measure_suite(
            recorded,
            rule_id=self.meta.id,
            case_ids=[case.case_id for case in self.cases],
            trials_per_case=self.trials_per_case,
            gate=self.gate,
            dataset=self.dataset,
            dataset_digest=self.dataset_digest,
            evaluators=ctx.evaluators,
            calibrations=ctx.calibrations,
            sample=self.sample,
            starter_digest=_starter_digest(),
        )

    def _measure(self, target: Target, ctx: RuleContext, start: int) -> Iterable[Finding]:
        if not isinstance(target, ChatEndpoint):
            raise RuleError(f"{self.meta.id} needs a chat endpoint, got {type(target).__name__}")
        evaluator_id = self.meta.evaluator or ""
        evaluator = ctx.evaluators.get(evaluator_id)
        if evaluator is None:
            raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
        failing: dict[str, str] = {}
        for case in self.cases:
            for trial in range(1, self.trials_per_case + 1):
                try:
                    sent = send(target, case.messages)
                except ReplyUnavailable as exc:
                    # Kept in the denominator as ungraded, under the assessor the graded
                    # trials carry, so one missing reply never splits the suite's grading.
                    ctx.record(
                        _unavailable(
                            exc,
                            case=case,
                            assessor=evaluator.assessor_id,
                            subject_ref=target.ref,
                            rule_id=self.meta.id,
                            dataset=self.dataset,
                            trial=trial,
                        )
                    )
                    continue
                # A case may script assistant turns; only the model's reply is graded.
                exchange = answered(case.messages, sent, graded_from=len(case.messages))
                verdict, from_decline = grade_decline(evaluator, exchange, case.expectation)
                ctx.record(
                    from_verdict(
                        verdict,
                        case_id=case.case_id,
                        subject_ref=target.ref,
                        rule_id=self.meta.id,
                        dataset=self.dataset,
                        tags=(*case.tags, *decline_tags(exchange, from_decline)),
                        trial=trial,
                        reason=decline_reason(exchange),
                    )
                )
                if verdict.outcome == "fail" and len(failing) < _EVIDENCE_CASES:
                    failing.setdefault(case.case_id, sent.evidence)
        recorded = ctx.recorded()[start:]
        summary = self._summary(ctx, recorded)
        ctx.conclude(summary)
        if summary.outcome is not SuiteOutcome.PASS:
            assessor = summary.correction.assessor or next(
                (a.assessor for a in recorded), evaluator_id
            )
            yield self._finding(summary, failing, assessor, target.ref)

    def _finding(
        self, summary: SuiteSummary, failing: dict[str, str], assessor: str, target_ref: str
    ) -> Finding:
        declined = summary.outcome is SuiteOutcome.INCONCLUSIVE
        statement = describe(summary)
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target_ref,
            evidence=Evidence(summary=statement, detail=_failing_cases(failing)),
            # Certain when it failed: the verdict is a comparison of a measured rate with
            # the bar, and a lower number would let a policy's `min_confidence` drop it.
            verdict=Verdict(
                outcome="inconclusive" if declined else "fail",
                confidence=0.0 if declined else 1.0,
                rationale=statement,
                evaluator_id=assessor,
            ),
        )


def _unavailable(  # noqa: PLR0913 — one keyword per fact the exception cannot supply
    exc: ReplyUnavailable,
    *,
    case: SuiteCase,
    assessor: str,
    subject_ref: str,
    rule_id: str,
    dataset: str,
    trial: int,
) -> Assessment:
    """Record a trial the recording could not answer: never graded, never a pass."""
    status = (
        AssessmentStatus.ERROR
        if exc.reason is UnmeasuredReason.NOT_RECORDED
        else AssessmentStatus.INCONCLUSIVE
    )
    return Assessment(
        case_id=case.case_id,
        assessor=assessor,
        subject_ref=subject_ref,
        status=status,
        rule_id=rule_id,
        passed=None,
        dataset=dataset,
        rationale=str(exc),
        tags=case.tags,
        trial=trial,
        reason=exc.reason,
    )


def _stopped_reason(summary: SuiteSummary) -> str:
    return (
        f"the budget ran out before every case was measured: "
        f"{summary.measured} of {summary.cases} cases measured"
    )


def _failing_cases(failing: dict[str, str]) -> str:
    return "\n".join(f"{case_id}: {reply}" for case_id, reply in failing.items())


def select_sample(cases: Sequence[SuiteCase], size: int, seed: int) -> tuple[SuiteCase, ...]:
    """Choose `size` cases by a hash of the seed and each case id, keeping dataset order.

    A hash rather than `random.sample`, whose algorithm is not promised across Python
    versions: the same seed must choose the same cases on every build.
    """
    ranked = sorted(
        cases,
        key=lambda case: hashlib.sha256(f"{seed}:{case.case_id}".encode()).hexdigest(),
    )
    chosen = {case.case_id for case in ranked[:size]}
    return tuple(case for case in cases if case.case_id in chosen)


@cache
def _starter_digest() -> str:
    """Return the digest of the bundled starter corpus, which never corrects a real run."""
    return corpus_digest(bundled_corpus())
