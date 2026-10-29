from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import NotOffered, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    A2aAnswer,
    A2aCallers,
    A2aReply,
    A2aView,
    Capability,
    TargetKind,
)
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_ASI07_2026
from guardana.rules.a2a import _samples
from guardana.rules.a2a._base import A2aRule


class A2aTaskVisibilityRule(A2aRule):
    """An A2A agent that shows one caller's tasks to somebody else.

    A task holds what a caller asked an agent to do and what came back. Three ways to
    see one that is not yours: an anonymous `ListTasks` that lists any task at all —
    a caller presenting nothing owns none, so they are somebody else's — and a second
    caller, or a caller presenting nothing, reading by id a task the first caller listed
    as its own.

    The reads by id need two credentials for two different callers
    (`--a2a-token-env` and `--a2a-other-token-env`) and a card whose security a bearer
    token can satisfy; without them they are inconclusive, and so is the listing when the
    anonymous `ListTasks` met neither a result nor a refusal. Only reads are sent; no task is
    created. A "task not found" is never graded, since the specification asks an
    agent not to tell "absent" from "not yours". An agent that answers every
    `ListTasks` it was sent as an operation it does not support has no listing to
    grade, which the run records as not offered.
    """

    meta = RuleMeta(
        id="guardana.a2a.task_visibility",
        title="A2A agent shows a task to a caller who does not own it",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_ASI03_2026, OWASP_ASI07_2026),
        required_capabilities=frozenset({Capability.INSPECT_A2A}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    @property
    def estimated_requests(self) -> int:
        """The card, three anonymous reads, the listing, three cross reads, one anonymous read."""
        return 9

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a shared owner, an owner-bound agent, a missing second caller, no listing."""
        return materialise(
            (
                _samples.sample(
                    "every task stored under one owner",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(owner_bound=False),
                ),
                _samples.sample(
                    "tasks bound to the caller who owns them",
                    FixtureOutcome.CLEAN,
                    _samples.target,
                ),
                _samples.sample(
                    "no second caller's credential",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(other=None),
                ),
                _samples.sample(
                    "ListTasks answered as an unsupported operation",
                    FixtureOutcome.NOT_OFFERED,
                    lambda: _samples.target(errors={"ListTasks": -32004}),
                ),
            )
        )

    def examine(self, view: A2aView) -> Iterator[Finding]:
        """Grade the anonymous listing, then the reads of the first caller's tasks by others.

        The anonymous listing is graded before the callers' section is read, so a run the
        second caller's requests stop still reports it. A listing that was graded is one
        the agent offers, so `NotOffered` is never raised after a report.
        """
        anonymous = view.anonymous
        unsupported = view.unsupported
        if unsupported is not None:
            yield self.unverified(
                view, f"whether tasks are kept per caller is unknown: {unsupported}"
            )
            return
        listed = anonymous.list_tasks
        if listed is not None and listed.lists_tasks:
            yield self.finding(
                view,
                f"ListTasks shows {_count(listed)} task(s) to a caller presenting no "
                f"credential, who owns none",
            )
        elif listed is not None and listed.answer is A2aAnswer.OTHER:
            yield self.unverified(
                view,
                f"whether a caller presenting no credential is shown tasks is unknown: "
                f"ListTasks met {listed.detail}",
            )
        callers = view.callers
        listings = [
            reply
            for reply in (listed, callers.first_listing)
            if reply is not None and reply.answer is not A2aAnswer.REFUSED
        ]
        if listings and all(reply.answer is A2aAnswer.NOT_OFFERED for reply in listings):
            raise NotOffered(
                "the agent answers ListTasks as an operation it does not offer",
                missing=("ListTasks",),
            )
        yield from self._anonymous_read(view, callers.anonymous_read)
        yield from self._across(view, callers)

    def _anonymous_read(self, view: A2aView, read: A2aReply | None) -> Iterator[Finding]:
        """Grade a caller presenting nothing asking for one of the first caller's tasks by id."""
        if read is None:
            return
        if read.answer is A2aAnswer.ANSWERED:
            yield self.finding(
                view,
                "a caller who presented no credential read the first caller's task by its "
                "id through GetTask",
            )
        elif read.answer not in (A2aAnswer.REFUSED, A2aAnswer.NOT_FOUND):
            yield self.unverified(
                view,
                f"whether a caller presenting no credential can read the first caller's task "
                f"is unknown: GetTask met {read.detail}",
            )

    def _across(self, view: A2aView, callers: A2aCallers) -> Iterator[Finding]:
        """Grade the second caller reading the first caller's tasks, or say why it was not."""
        unsettled = "whether one caller can read another's task is unknown"
        if callers.not_sent_because is not None:
            yield self.unverified(view, f"{unsettled}: {callers.not_sent_because}")
            return
        first = callers.first_listing
        if first is None or first.answer is not A2aAnswer.ANSWERED:
            said = "it was not sent" if first is None else f"it met {first.detail}"
            yield self.unverified(view, f"{unsettled}: the first caller's ListTasks failed, {said}")
            return
        if callers.first_tasks == 0:
            yield self.unverified(
                view,
                f"{unsettled}: the first caller listed no task with an id, so there was none "
                f"for the second caller to ask for",
            )
            return
        read = [reply for reply in callers.second if reply.answer is A2aAnswer.ANSWERED]
        if read:
            yield self.finding(
                view,
                f"a second caller read {len(read)} of {len(callers.second)} task(s) the first "
                f"caller listed as its own",
            )
            return
        open_reads = [reply for reply in callers.second if reply.answer is not A2aAnswer.NOT_FOUND]
        if open_reads:
            yield self.unverified(view, f"{unsettled}: {_answers(open_reads)}")


def _count(reply: A2aReply) -> int:
    return max(reply.listed, reply.total_size or 0)


def _answers(replies: list[A2aReply]) -> str:
    """Say what the second caller met where it was neither shown a task nor told none exists."""
    refused = [reply for reply in replies if reply.answer is A2aAnswer.REFUSED]
    if refused:
        return (
            f"the second caller was refused ({refused[0].detail}), so its credential was not "
            f"accepted; check the variable --a2a-other-token-env names"
        )
    return "the second caller's GetTask met " + "; ".join(reply.detail for reply in replies)
