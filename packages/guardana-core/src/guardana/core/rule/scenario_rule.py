from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace

from guardana.core.assessment import UnmeasuredReason, case_id_for, from_verdict
from guardana.core.evaluator.base import (
    Evaluator,
    Expectation,
    Verdict,
    earlier_failure,
    grade_decline,
)
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule._send import decline_reason, decline_tags, send
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.rule.fixture import DeclaredFixture, RuleFixture, materialise
from guardana.core.target import ChatMessage, Decline, Target
from guardana.core.target.protocols import ChatEndpoint
from guardana.core.trials import CaseOutcome, case_outcome, check_trials, failed_before_stop


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    """One turn of a scenario: the message to send, and an optional per-turn grade."""

    send: str
    evaluator: str | None = None
    expect: Expectation | None = None


@dataclass(frozen=True, slots=True)
class ScenarioRule(Rule):
    """A dynamic rule that drives a multi-turn conversation and grades it.

    Each turn's message is sent in order; a step may grade its own reply, and the
    whole conversation may be graded at the end. Everything a single-turn `YamlRule`
    could not express — a jailbreak that needs a setup, a leak that builds over
    turns — lives here, still authored declaratively in YAML.
    """

    meta: RuleMeta
    steps: tuple[ScenarioStep, ...]
    stateful: bool = False
    conversation_evaluator: str | None = None
    conversation_expect: Expectation | None = None
    source_digest: str = ""
    """Hash of the declaration this rule was parsed from; see `Rule.digest`."""

    declared_fixtures: tuple[RuleFixture | DeclaredFixture, ...] = ()
    """Samples from the rule file's `fixtures:` block, one reply per step."""

    trials_per_case: int = 1
    """How many times `run` walks the whole conversation afresh; set by `with_trials`."""

    def fixtures(self) -> Iterable[RuleFixture]:
        """Build this rule file's samples, each with a double that has played nothing."""
        return materialise(self.declared_fixtures)

    def digest(self) -> str:
        """Return the declaration hash, falling back to the metadata-only default.

        A rule built by hand rather than parsed (a test, or a plugin assembling one
        programmatically) has no declaration to hash, and the base implementation
        still gives it a stable identity.

        `Rule.digest(self)` rather than `super().digest()`, and that is not style.
        `@dataclass(slots=True)` builds a *new* class object and throws the
        original away, while the zero-argument `super()` closure still points at
        the original — so the call raises `TypeError` every time it is reached.
        It was reached only when `source_digest` was empty, which is exactly the
        hand-built case no fixture had, so it sat here undetected until something
        started asking every rule for its digest.
        """
        return self.source_digest or Rule.digest(self)

    @property
    def estimated_requests(self) -> int:
        """One request per step per trial: a conversation has to be walked through in order."""
        return len(self.steps) * self.trials_per_case

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """One verdict per graded step and one for the conversation, per trial, by evaluator.

        Keyed by each scope's own evaluator: a scenario's steps may grade with different
        evaluators, and its `meta.evaluator` names none of them.
        """
        graded = [s.evaluator or "" for s in self.steps if s.expect is not None]
        if self.conversation_expect is not None:
            graded.append(self.conversation_evaluator or "")
        counts: dict[str, int] = {}
        for evaluator_id in graded:
            counts[evaluator_id] = counts.get(evaluator_id, 0) + self.trials_per_case
        return counts

    @property
    def grades_one_case(self) -> bool:
        """Every graded turn and the whole-conversation grade are checkpoints of one walk."""
        return True

    def with_trials(self, trials: int) -> "Rule | None":
        """Walk the conversation `trials` times, each from an empty history.

        None for a `stateful` scenario: the endpoint keeps that conversation, and
        nothing here can open a fresh session, so a second trial would continue the
        first and two attempts would be one longer conversation.
        """
        if self.stateful:
            return None
        return replace(self, trials_per_case=check_trials(trials))

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Every grade the scenario carries: one per graded step, plus the conversation."""
        pairs = [(s.evaluator, s.expect) for s in self.steps]
        pairs.append((self.conversation_evaluator, self.conversation_expect))
        return tuple((e, x) for e, x in pairs if e is not None and x is not None)

    def with_canary(self, canary: str) -> "Rule | None":
        """Swap every declared canary — per-step and whole-conversation — for the planted one.

        All of them, because a scenario that graded one step against the shipped
        marker and the conversation against the planted one would look configured
        and check nothing on the step.
        """
        expectations = [step.expect for step in self.steps] + [self.conversation_expect]
        if not any(e is not None and e.canary for e in expectations):
            return None
        steps = tuple(replace(s, expect=_planted(s.expect, canary)) for s in self.steps)
        return replace(
            self, steps=steps, conversation_expect=_planted(self.conversation_expect, canary)
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Drive the turns once per trial, grade each `expect`, and the conversation at the end.

        A walk stops at a step the application declines: that step and the conversation
        are graded with the decline, and every graded step it did not reach is recorded
        `inconclusive`, so a trial never loses a case.
        """
        if not isinstance(target, ChatEndpoint):
            # Unreachable while the capability contract holds: the runner only
            # plans this rule against a target that declared `chat`. If it ever
            # runs, the contract is broken, and that belongs in `errors` rather
            # than looking like a rule that ran and found nothing.
            raise RuleError(f"{self.meta.id} needs a chat endpoint, got {type(target).__name__}")
        graded: dict[str, list[tuple[_GradedScope, Verdict, str]]] = {}
        try:
            for trial in range(1, self.trials_per_case + 1):
                for scope, grading in self._conversation(target, ctx):
                    # The scope is part of the case id: a scenario grades the same
                    # conversation per turn and again whole, and folding those together
                    # would count one exchange as two measurements of the same thing.
                    case_id = case_id_for(self.meta.id, scope.name, scope.case_key)
                    ctx.record(
                        from_verdict(
                            grading.verdict,
                            case_id=case_id,
                            subject_ref=target.ref,
                            rule_id=self.meta.id,
                            dataset=self.digest(),
                            tags=(scope.name, *grading.tags),
                            trial=trial,
                            reason=grading.reason,
                        )
                    )
                    graded.setdefault(case_id, []).append(
                        (scope, grading.verdict, grading.transcript)
                    )
        except Exception:
            # A failure already seen is kept when a later trial stops the rule: a
            # spent budget or a grader that raised must not take it back.
            for trials in graded.values():
                partial = failed_before_stop([v for _s, v, _t in trials], self.trials_per_case)
                if partial is not None:
                    yield self._finding(partial, trials, target.ref)
            raise
        for trials in graded.values():
            # `fail` is a finding; a case with a trial that could not be graded is
            # surfaced too (the runner routes it to `unverified`). Only a case whose
            # every trial passed yields nothing.
            outcome = case_outcome([verdict for _scope, verdict, _transcript in trials])
            if outcome is not None:
                yield self._finding(outcome, trials, target.ref)

    def _finding(
        self,
        outcome: CaseOutcome,
        trials: list[tuple["_GradedScope", Verdict, str]],
        target_ref: str,
    ) -> Finding:
        """One case's finding, with the transcript of the trial its verdict came from."""
        scope, _verdict, transcript = trials[outcome.trial - 1]
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target_ref,
            evidence=Evidence(
                summary=f"[{scope.name}] {outcome.verdict.rationale}", detail=transcript
            ),
            verdict=outcome.verdict,
        )

    def _conversation(
        self, target: ChatEndpoint, ctx: RuleContext
    ) -> Iterator[tuple["_GradedScope", "_Grading"]]:
        """Walk the turns from an empty history once, grading every scope as it comes."""
        messages: list[ChatMessage] = []
        meta: Mapping[str, str] = {}
        declined: Decline | None = None
        # Where each grader stopped reading, by evaluator and expectation.
        read_until: list[tuple[str | None, Expectation, int]] = []
        for index, step in enumerate(self.steps):
            messages.append(ChatMessage(role="user", content=step.send))
            to_send = [messages[-1]] if self.stateful else list(messages)
            sent = send(target, to_send)
            meta, declined = sent.meta, sent.decline
            if declined is None:
                messages.append(ChatMessage(role="assistant", content=sent.text or ""))
            if step.expect is not None:
                scope = _GradedScope(_resolve(ctx, step.evaluator), step.expect, "turn", step.send)
                start = _read_from(read_until, step.evaluator, scope.expectation, len(messages))
                exchange = Exchange(tuple(messages), meta=meta, graded_from=start, decline=declined)
                yield scope, _graded(scope, exchange)
            if declined is not None:
                walked = Exchange(tuple(messages), meta=meta, decline=declined)
                yield from _unreached(ctx, self.steps[index + 1 :], walked, declined, read_until)
                break
        if self.conversation_expect is not None:
            scope = _GradedScope(
                _resolve(ctx, self.conversation_evaluator),
                self.conversation_expect,
                "conversation",
                "",
            )
            exchange = Exchange(tuple(messages), meta=meta, decline=declined)
            yield scope, _graded(scope, exchange)


@dataclass(frozen=True, slots=True)
class _GradedScope:
    """One place a scenario grades: which judge, against what, and which case it is.

    Four values that always travel together — separating them into parameters made
    the call a positional list nobody could read, and one of them the case id
    depends on.
    """

    evaluator: Evaluator
    expectation: Expectation
    name: str
    case_key: str


@dataclass(frozen=True, slots=True)
class _Grading:
    """One scope's verdict, the transcript it read, and what its assessment records beside it."""

    verdict: Verdict
    transcript: str
    tags: tuple[str, ...]
    reason: UnmeasuredReason | None


def _graded(scope: _GradedScope, exchange: Exchange) -> _Grading:
    """Grade `exchange` for `scope`, a decline included."""
    verdict, from_decline = grade_decline(scope.evaluator, exchange, scope.expectation)
    return _Grading(
        verdict,
        exchange.transcript,
        decline_tags(exchange, from_decline),
        decline_reason(exchange),
    )


def _read_from(
    read_until: list[tuple[str | None, Expectation, int]],
    evaluator_id: str | None,
    expect: Expectation,
    end: int,
) -> int:
    """Return where a step's grader starts reading, and mark it as read up to `end`.

    A step grades the replies since the last step graded by the same evaluator against the
    same expectation: that grader reads each reply once, and a reply another grader checked
    is still read by it.
    """
    start = next(
        (
            until
            for evaluator, expectation, until in reversed(read_until)
            if evaluator == evaluator_id and expectation == expect
        ),
        0,
    )
    read_until.append((evaluator_id, expect, end))
    return start


def _unreached(
    ctx: RuleContext,
    later: tuple[ScenarioStep, ...],
    walked: Exchange,
    decline: Decline,
    read_until: list[tuple[str | None, Expectation, int]],
) -> Iterator[tuple[_GradedScope, _Grading]]:
    """Grade every graded step a decline kept from being sent, over the turns that were.

    A reply its grader had not yet read can still fail the step: a leak before the decline
    stands. Otherwise the step is not measured. A step never sent has no decline of its
    own, so `read_decline` is never asked about it.
    """
    for step in later:
        if step.expect is None:
            continue
        scope = _GradedScope(_resolve(ctx, step.evaluator), step.expect, "turn", step.send)
        start = _read_from(read_until, step.evaluator, scope.expectation, len(walked.messages))
        exchange = replace(walked, graded_from=start)
        failed = earlier_failure(scope.evaluator, exchange, scope.expectation)
        if failed is not None:
            yield scope, _Grading(failed, exchange.transcript, (), None)
            continue
        verdict = Verdict(
            "inconclusive",
            0.0,
            f"not sent: an earlier step was {decline.described}",
            scope.evaluator.assessor_id,
        )
        yield (
            scope,
            _Grading(
                verdict, exchange.transcript, (decline.tag,), UnmeasuredReason.TARGET_DECLINED
            ),
        )


def _planted(expect: Expectation | None, canary: str) -> Expectation | None:
    """Point one expectation at the planted token, leaving canary-free ones alone."""
    return replace(expect, canary=canary) if expect is not None and expect.canary else expect


def _resolve(ctx: RuleContext, evaluator_id: str | None) -> Evaluator:
    """Resolve an evaluator from the registry, failing loudly when the id is absent."""
    evaluator = ctx.evaluators.get(evaluator_id or "")
    if evaluator is None:
        raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
    return evaluator
