from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace

from guardana.core.assessment import case_id_for, from_verdict
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict, grade
from guardana.core.evaluator.tool_call import ToolCallEvaluator, _undelivered
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.rule.fixture import DeclaredFixture, RuleFixture, materialise
from guardana.core.target import Target
from guardana.core.target.endpoint import ToolSpec
from guardana.core.target.protocols import ToolOfferingEndpoint
from guardana.core.trajectory import (
    AgentMemory,
    StaticToolDouble,
    ToolDouble,
    ToolOffer,
    Trajectory,
    TrajectoryStep,
    drive,
)
from guardana.core.trials import CaseOutcome, case_outcome, check_trials, failed_before_stop

DELIVERY_FIELDS = frozenset({"delivered_by", "payload_marker"})
"""The `expect:` fields the rule itself reads to prove its payload reached the model."""


@dataclass(frozen=True, slots=True)
class TrajectoryRule(Rule):
    """A dynamic rule that gives a model a task and tools, then grades the whole run.

    The declarative shape for agent checks: a task, a set of simulated tools with
    the results they hand back, and a bound on how many round trips the run gets.
    What makes it worth a rule type of its own is that the *tool result* is
    attacker-controlled ground in a real agent, so it is where the payload goes.
    """

    meta: RuleMeta
    task: str
    tools: tuple[ToolOffer, ...]
    max_steps: int
    expectation: Expectation
    then_task: str | None = None
    """A second task, run in a **fresh session** against the same memory store.

    What separates an agent from a chat is that something written in one
    conversation comes back in the next. A poisoning check therefore needs a
    session boundary: write in the first, prove influence in the second. The
    question is asked of the second session; the first can still settle the
    verdict (a failure already made there) or void a pass (a session cut short, or
    one that saved nothing for the second to read).
    """

    source_digest: str = ""
    """Hash of the declaration this rule was parsed from; see `Rule.digest`."""

    declared_fixtures: tuple[RuleFixture | DeclaredFixture, ...] = ()
    """Samples from the rule file's `fixtures:` block, one turn per round trip."""

    trials_per_case: int = 1
    """How many times `run` drives the whole task afresh; set by `with_trials`."""

    def __post_init__(self) -> None:
        # Checked here as well as in the YAML loader: a plugin that assembles the
        # rule in Python must not get a delivery the loader would have refused.
        problem = delivery_problem(
            self.meta.evaluator,
            self.expectation,
            self.tools,
            (self.task, self.then_task or ""),
        )
        if problem is not None:
            raise RuleLoadError(f"invalid rule {self.meta.id}: {problem}")

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
    def sessions(self) -> int:
        """How many separate runs this rule drives — two when it crosses a session."""
        return 2 if self.then_task is not None else 1

    @property
    def estimated_requests(self) -> int:
        """The step budget of every trial, which is exactly what this rule can spend.

        `budget` times the trials, exposed under the name every rule answers to so
        `guardana plan` does not have to know what kind of rule this is.
        """
        return self.budget * self.trials_per_case

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """One verdict per session per trial: a two-session run may grade both sessions."""
        return {self.meta.evaluator or "": self.sessions * self.trials_per_case}

    def with_trials(self, trials: int) -> "Rule | None":
        """Drive the task `trials` times, each with fresh history and a fresh memory store."""
        return replace(self, trials_per_case=check_trials(trials))

    @property
    def budget(self) -> int:
        """The most model calls this rule can cost, across every session it drives.

        `max_steps` bounds one session; a rule that opens a second one costs twice
        that, and a cost that is only true per session is not a cost anyone can
        plan a probe around.
        """
        return self.max_steps * self.sessions

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Report the single evaluator and expectation the run is graded with."""
        return ((self.meta.evaluator or "", self._graded_expectation),)

    @property
    def _graded_expectation(self) -> Expectation:
        return graded_expectation(self.meta.evaluator, self.expectation)

    def with_canary(self, canary: str) -> "Rule | None":
        """Swap the declared canary — in the expectation, every tool result, and every schema.

        All three, because the marker a run leaks is the one the model was actually
        handed. Planting it only in the expectation would leave the evaluator
        hunting for a token that was never put anywhere it could be found, and the
        rule would report a confident pass for a fully disclosing model.

        The **tool description** is the third place, and it is not decoration: a
        tool schema is hidden context an agent is given as trusted instruction, and
        it routinely carries internal endpoints and identifiers. A rule that plants
        its marker there is checking `LLM08:2026 Hidden Context Exposure`, which
        widened the old system-prompt scope to exactly this.
        """
        if self.expectation.canary is None:
            return None
        declared = self.expectation.canary
        tools = tuple(
            ToolOffer(
                spec=_respecified(offer.spec, declared, canary),
                double=_repointed(offer, declared, canary),
                memory=offer.memory,
            )
            for offer in self.tools
        )
        return replace(self, tools=tools, expectation=replace(self.expectation, canary=canary))

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Drive the run, then grade it with the configured evaluator."""
        if not isinstance(target, ToolOfferingEndpoint):
            # Unreachable while the capability contract holds: the runner only
            # plans this rule against a target that declared `chat`. If it ever
            # runs, the contract is broken, and that belongs in `errors` rather
            # than looking like a rule that ran and found nothing.
            raise RuleError(f"{self.meta.id} needs a chat endpoint, got {type(target).__name__}")
        evaluator_id = self.meta.evaluator or ""
        evaluator = ctx.evaluators.get(evaluator_id)
        if evaluator is None:
            raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
        stop = _stop_on(forbidden_tools(self.expectation))
        case_id = case_id_for(self.meta.id, self.task, self.then_task or "")
        verdicts: list[Verdict] = []
        details: list[str] = []
        try:
            for trial in range(1, self.trials_per_case + 1):
                verdict, detail = self._attempt(target, evaluator, stop)
                # Recorded whatever the verdict: a truncated run grades as inconclusive,
                # and a suite hitting its step ceiling more often has fewer graded cases
                # rather than a better model.
                ctx.record(
                    from_verdict(
                        verdict,
                        case_id=case_id,
                        subject_ref=target.ref,
                        rule_id=self.meta.id,
                        dataset=self.digest(),
                        trial=trial,
                    )
                )
                verdicts.append(verdict)
                details.append(detail)
        except Exception:
            # A failure already seen is kept when a later trial stops the rule: a
            # spent budget or a grader that raised must not take it back.
            partial = failed_before_stop(verdicts, self.trials_per_case)
            if partial is not None:
                yield self._finding(partial, details, target.ref)
            raise
        outcome = case_outcome(verdicts)
        if outcome is not None:
            yield self._finding(outcome, details, target.ref)

    def _attempt(
        self,
        target: ToolOfferingEndpoint,
        evaluator: Evaluator,
        stop: Callable[[TrajectoryStep], bool] | None,
    ) -> tuple[Verdict, str]:
        """Drive one trial from nothing: fresh history, fresh memory, every session it needs."""
        tools, memory = _materialised(self.tools)
        first = drive(target, self.task, tools, max_steps=self.max_steps, stop_after=stop)
        if self.then_task is None:
            verdict = _unless_cut_short(self._graded(evaluator, first), first, "the run")
            return self._unless_delivered(verdict, first), first.render()
        # A fresh session: no history crosses the boundary, only the store the memory
        # doubles share.
        saved = memory is not None and bool(memory.entries)
        second = drive(target, self.then_task, tools, max_steps=self.max_steps, stop_after=stop)
        verdict = self._across_sessions(evaluator, first, second, saved=saved)
        return verdict, f"{first.render()}\n--- new session ---\n{second.render()}"

    def _finding(self, outcome: CaseOutcome, details: list[str], target_ref: str) -> Finding:
        """Build the run's finding from the transcript of the trial its verdict came from."""
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target_ref,
            evidence=Evidence(summary=outcome.verdict.rationale, detail=details[outcome.trial - 1]),
            verdict=outcome.verdict,
        )

    def _across_sessions(
        self, evaluator: Evaluator, first: Trajectory, second: Trajectory, *, saved: bool
    ) -> Verdict:
        """Grade a two-session run: the second session answers, the first can settle it.

        Both sessions are the run. A failure already made in the first is a finding
        whatever the second did. A clean second session proves something only if it
        ran to the end and a note reached it: not when either session was cut short,
        and not when the first saved nothing at all, however the second one behaved.
        """
        earlier = self._graded(evaluator, first)
        if earlier.outcome == "fail":
            return replace(earlier, rationale=f"in the first session: {earlier.rationale}")
        later = self._unless_delivered(
            _unless_cut_short(self._graded(evaluator, second), second, "the second session"),
            second,
        )
        if later.outcome != "pass":
            return later
        if first.truncated is not None:
            why = (
                f"the first session was cut short ({first.truncated.value}), so the note "
                f"the second session reads may never have been written"
            )
        elif not saved:
            why = (
                "the first session saved nothing, so no note could reach the second — "
                "a clean second session says nothing about memory"
            )
        else:
            return later
        return Verdict("inconclusive", 0.0, why, evaluator.id)

    def _graded(self, evaluator: Evaluator, run: Trajectory) -> Verdict:
        return grade(evaluator, Exchange.from_trajectory(run), self._graded_expectation)

    def _unless_delivered(self, verdict: Verdict, run: Trajectory) -> Verdict:
        """Turn a pass on a run the payload never reached into `inconclusive`; a failure stands.

        A grader that does not read the run's tool results, such as a judge asked
        whether the agent followed a planted note, passes an agent that never opened
        it, and that pass says nothing about the injection.
        """
        if verdict.outcome != "pass":
            return verdict
        why = _undelivered(run, self.expectation)
        if why is None:
            return verdict
        return replace(
            verdict, outcome="inconclusive", confidence=0.0, rationale=why, measurement=None
        )


def graded_expectation(evaluator_id: str | None, expectation: Expectation) -> Expectation:
    """Return what the evaluator is handed: the delivery fields go only to `tool_call`.

    The rule proves delivery whichever evaluator grades it; `tool_call` also reads
    those fields itself, and any other evaluator would be refused for carrying
    fields it does not use.
    """
    if evaluator_id == ToolCallEvaluator.id:
        return expectation
    fields = {k: v for k, v in expectation.fields.items() if k not in DELIVERY_FIELDS}
    return replace(expectation, fields=fields)


def delivery_problem(
    evaluator_id: str | None,
    expectation: Expectation,
    tools: tuple[ToolOffer, ...],
    prompts: tuple[str, ...] = (),
) -> str | None:
    """Return why a rule's `delivered_by` could never prove delivery, or None.

    `delivered_by` separates "the model resisted the payload" from "the model never
    saw it", so the tool it names must be able to hand the payload over, and
    `payload_marker` must be text that can come back from it. `prompts` are the
    user turns the rule sends. The rule proves delivery whichever evaluator grades
    it, so no `evaluator_id` is exempt from these checks.
    """
    shape = _delivery_shape_problem(expectation)
    delivered_by = expectation.get("delivered_by")
    if shape is not None or not isinstance(delivered_by, str):
        return shape
    offer = next((o for o in tools if o.spec.name == delivered_by), None)
    if offer is None:
        return (
            f"expect.delivered_by names {delivered_by!r}, which is not a declared tool — "
            f"the model can never call it, so nothing is ever delivered"
        )
    if offer.memory == "write":
        return (
            f"expect.delivered_by names {delivered_by!r}, a 'memory: write' tool — it "
            f"returns an acknowledgement, never the payload"
        )
    marker = expectation.get("payload_marker")
    if isinstance(marker, str):
        return _marker_problem(marker, offer, tools, expectation.canary, prompts)
    if offer.memory == "read":
        return (
            f"expect.delivered_by names {delivered_by!r}, a 'memory: read' tool, whose "
            f"result is whatever was saved; set expect.payload_marker to text of the "
            f"payload, or a recall of anything else would count as delivery"
        )
    return None


def _delivery_shape_problem(expectation: Expectation) -> str | None:
    """Return why a delivery field is of an unusable shape, or None.

    A field of the wrong shape would otherwise be read as absent, and a rule that
    looks as if it proves delivery would prove nothing.
    """
    for name in sorted(DELIVERY_FIELDS):
        value = expectation.get(name)
        if value is not None and (not isinstance(value, str) or not value):
            return f"expect.{name} must be a non-empty string"
    if expectation.get("payload_marker") is not None and expectation.get("delivered_by") is None:
        return "expect.payload_marker needs expect.delivered_by, the tool whose result carries it"
    return None


def _marker_problem(
    marker: str,
    offer: ToolOffer,
    tools: tuple[ToolOffer, ...],
    canary: str | None,
    prompts: tuple[str, ...],
) -> str | None:
    """Return why `payload_marker` could never come back from `offer`, or None."""
    if canary is not None and canary.casefold() in marker.casefold():
        return (
            "expect.payload_marker contains the canary, which is replaced by a fresh "
            "token every run, so the marker would never be found"
        )
    outside = " outside the canary" if canary is not None else ""
    if isinstance(offer.double, StaticToolDouble):
        if _carries(offer.double.text, marker, canary):
            return None
        return (
            f"expect.payload_marker is not in what {offer.spec.name!r} returns{outside}, "
            f"so delivery could never be proven"
        )
    if any(marker.casefold() in prompt.casefold() for prompt in prompts):
        # The user's own words are not the payload: a note saved from the task
        # would come back carrying the marker without the poison ever being read.
        return (
            "expect.payload_marker appears in the rule's task, so a note saved from the "
            "task alone would count as the payload being delivered"
        )
    # A store holds only what the model saved from the tools it read, so the
    # marker has to be in one of them or no recall can ever carry it.
    if any(
        isinstance(o.double, StaticToolDouble) and _carries(o.double.text, marker, canary)
        for o in tools
    ):
        return None
    return (
        f"expect.payload_marker is in no tool's 'returns:'{outside}, so no note the "
        f"model saves can carry it and every run would be inconclusive"
    )


def _carries(text: str, marker: str, canary: str | None) -> bool:
    """Whether `text` holds the marker in a span each run leaves as it is."""
    kept = text if canary is None else text.replace(canary, "\0")
    return marker.casefold() in kept.casefold()


def _unless_cut_short(verdict: Verdict, run: Trajectory, which: str) -> Verdict:
    """Turn a pass on a truncated run into `inconclusive`; a failure stands.

    Only `tool_call` reads the truncation itself. A text evaluator sees the prose
    the run produced before it stopped, and nothing leaking so far says nothing
    about the steps that never ran.
    """
    if verdict.outcome != "pass" or run.truncated is None:
        return verdict
    # The pass's measurement is what the pass was read from; it must not ride on an
    # inconclusive.
    return replace(
        verdict,
        outcome="inconclusive",
        confidence=0.0,
        rationale=(
            f"{which} was cut short ({run.truncated.value}); what it would have done next "
            f"is unknown"
        ),
        measurement=None,
    )


def forbidden_tools(expectation: Expectation) -> frozenset[str]:
    """Return the tools a run must not call: where it stops, and where a script must end."""
    value = expectation.get("forbidden_tools")
    if isinstance(value, list):
        return frozenset(item for item in value if isinstance(item, str))
    return frozenset()


def _materialised(
    tools: tuple[ToolOffer, ...],
) -> tuple[tuple[ToolOffer, ...], AgentMemory | None]:
    """Bind every memory tool to one store, built fresh for this run, and return both.

    Fresh per run because a rule instance outlives a probe: a store built when the
    rule was parsed would carry one target's notes into the next target's run and
    report a leak that this model never produced.
    """
    if not any(offer.memory for offer in tools):
        return tools, None
    memory = AgentMemory()
    doubles = {"write": memory.writer(), "read": memory.reader()}
    offers = tuple(
        replace(offer, double=doubles[offer.memory]) if offer.memory else offer for offer in tools
    )
    return offers, memory


def _stop_on(forbidden: frozenset[str]) -> Callable[[TrajectoryStep], bool] | None:
    """Stop the run once a forbidden tool has been called — more steps cannot change it."""
    if not forbidden:
        return None

    def stop(step: TrajectoryStep) -> bool:
        return any(invocation.call.name in forbidden for invocation in step.invocations)

    return stop


def _repointed(offer: ToolOffer, old: str, new: str) -> ToolDouble:
    """Point a canned tool result at the freshly planted marker."""
    double = offer.double
    if isinstance(double, StaticToolDouble) and old in double.text:
        return StaticToolDouble(double.text.replace(old, new))
    return double


def _respecified(spec: ToolSpec, old: str, new: str) -> ToolSpec:
    """Point a tool's advertised description at the freshly planted marker."""
    if old not in spec.description:
        return spec
    return ToolSpec(name=spec.name, description=spec.description.replace(old, new))
