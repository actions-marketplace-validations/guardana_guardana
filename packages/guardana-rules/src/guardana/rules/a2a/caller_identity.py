from collections.abc import Iterable, Iterator, Sequence

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    A2aAnonymous,
    A2aAnswer,
    A2aSecurity,
    A2aView,
    Capability,
    TargetKind,
)
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_ASI07_2026
from guardana.rules.a2a import _samples
from guardana.rules.a2a._base import A2aRule

_METHOD_NOT_FOUND = -32601
_DECISIVE = frozenset({A2aAnswer.REFUSED, A2aAnswer.ANSWERED})


class A2aCallerIdentityRule(A2aRule):
    """An A2A agent that answers a caller presenting nothing.

    Three shapes, one finding each. A card that **requires** a credential and an agent
    that answers `GetTask`, `ListTasks` or `GetExtendedAgentCard` without one: the
    declaration is not enforced. A card that declares **no** security and an agent that
    answers one of them: nothing tells one caller from another, reported `low` when the
    agent is on a loopback or private address. And an extended card served to a caller
    presenting nothing, under any declaration: the extended card exists to say more to
    a caller the agent knows.

    An optional requirement makes an anonymous answer what the card declared, so only
    an undecided extended card is left open under it. A "task not found" is never
    graded: the specification asks an agent not to tell "absent" from "not yours", and
    a random id exists for nobody. So an agent that neither refused nor answered any
    anonymous read is inconclusive, never clean, and so is one whose card requires a
    credential and that answered an anonymous read with "task not found" rather than a
    refusal.
    """

    meta = RuleMeta(
        id="guardana.a2a.caller_identity",
        title="A2A agent answers a caller presenting no credential",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_ASI03_2026, OWASP_ASI07_2026),
        required_capabilities=frozenset({Capability.INSPECT_A2A}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    @property
    def estimated_requests(self) -> int:
        """The card, then an anonymous `GetTask`, `ListTasks` and extended card."""
        return 4

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample an unenforced declaration, an enforced one, and two agents it cannot grade."""
        elsewhere = _samples.card(
            supportedInterfaces=[
                {
                    "url": "https://elsewhere.invalid/a2a",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }
            ]
        )
        return materialise(
            (
                _samples.sample(
                    "a bearer requirement nothing enforces",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(enforced=False),
                ),
                _samples.sample(
                    "a bearer requirement enforced on every read",
                    FixtureOutcome.CLEAN,
                    _samples.target,
                ),
                _samples.sample(
                    "an agent that neither refuses nor answers a caller presenting nothing",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(enforced=False, errors={"ListTasks": -32004}),
                ),
                _samples.sample(
                    "a JSON-RPC interface on another origin",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(card=elsewhere),
                ),
            )
        )

    def examine(self, view: A2aView) -> Iterator[Finding]:
        """Report each shape of anonymous answer, or why the anonymous reads said nothing."""
        anonymous = view.anonymous
        unsupported = view.unsupported
        if unsupported is not None:
            yield self.unverified(
                view, f"whether the agent answers anyone is unknown: {unsupported}"
            )
            return
        extended = anonymous.extended_card
        extended_open = extended is not None and extended.answer is A2aAnswer.ANSWERED
        reads = (anonymous.get_task, anonymous.list_tasks, None if extended_open else extended)
        answered = [r.method for r in reads if r is not None and r.answer is A2aAnswer.ANSWERED]
        reported = False
        security = view.security
        if answered and security is A2aSecurity.REQUIRED:
            reported = True
            yield self.finding(
                view,
                f"the card requires a credential, and the agent answered {_listed(answered)} "
                f"to a caller presenting none",
            )
        elif answered and security is A2aSecurity.NONE:
            reported = True
            yield self._unguarded(view, answered)
        if extended_open:
            reported = True
            yield self.finding(
                view,
                "the agent served its extended card to a caller presenting no credential",
            )
        if not reported:
            yield from self._undecided(view, anonymous, security)

    def _unguarded(self, view: A2aView, answered: Sequence[str]) -> Finding:
        said = f"the card declares no security, and the agent answered {_listed(answered)} to a "
        if view.card_host_is_local:
            return self.finding(
                view,
                f"{said}caller presenting no credential; it is on a loopback or private "
                f"address, so the exposure is to whatever already runs there",
                severity=Severity.LOW,
            )
        return self.finding(
            view,
            f"{said}caller presenting no credential, on an address that is not loopback or private",
        )

    def _undecided(
        self, view: A2aView, anonymous: A2aAnonymous, security: A2aSecurity
    ) -> Iterator[Finding]:
        """Say why no anonymous answer settled the question, where the card leaves it open."""
        get_task = anonymous.get_task
        sent = anonymous.sent
        if (
            get_task is not None
            and get_task.answer is A2aAnswer.OTHER
            and get_task.code == _METHOD_NOT_FOUND
        ):
            yield self.unverified(
                view,
                "the agent answered GetTask as an unknown method before it answered anything "
                "A2A defines, so whether it speaks A2A 1.0 at all is unknown",
            )
            return
        if security is A2aSecurity.OPTIONAL and anonymous.extended_card is None:
            return
        if not any(reply.answer in _DECISIVE for reply in sent):
            said = "; ".join(f"{reply.method}: {reply.detail}" for reply in sent)
            yield self.unverified(
                view,
                "the agent neither refused nor answered a caller without a credential, so "
                "whether it requires one could not be shown" + (f" ({said})" if said else ""),
            )
            return
        unsettled = [
            f"{reply.method}: {reply.detail}" for reply in sent if reply.answer is A2aAnswer.OTHER
        ]
        if security is A2aSecurity.REQUIRED and unsettled:
            # One refused read says nothing about another method's guard, so a read that
            # met neither a refusal nor an answer is declined by name rather than dropped.
            yield self.unverified(
                view,
                f"the card requires a credential, and a caller presenting none met "
                f"{'; '.join(unsettled)}, which neither refuses nor answers, so whether "
                f"those methods check a credential could not be shown",
            )
        not_found = [reply.method for reply in sent if reply.answer is A2aAnswer.NOT_FOUND]
        if security is A2aSecurity.REQUIRED and not_found:
            yield self.unverified(
                view,
                f"the card requires a credential, and the agent answered {_listed(not_found)} "
                f"from a caller presenting none with task not found instead of refusing it, so "
                f"whether it checks a credential there could not be shown",
            )


def _listed(methods: Sequence[str]) -> str:
    return ", ".join(methods)
