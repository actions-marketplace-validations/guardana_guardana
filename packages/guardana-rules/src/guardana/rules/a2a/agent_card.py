from collections.abc import Iterable, Iterator
from urllib.parse import urlsplit

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import A2aView, Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI04_2026, OWASP_ASI07_2026
from guardana.rules.a2a import _samples
from guardana.rules.a2a._base import A2aRule

_REQUIRED_FIELDS = (
    "name",
    "description",
    "supportedInterfaces",
    "version",
    "capabilities",
    "defaultInputModes",
    "defaultOutputModes",
    "skills",
)


class A2aAgentCardRule(A2aRule):
    """An A2A agent card that leaves out what a caller needs to decide whether to trust it.

    The card is the agent's whole self-description: which skills it offers, how a
    caller must authenticate, and where to send requests. A required field missing
    leaves a client guessing; a security requirement naming a scheme the card never
    declares cannot be met by any caller, so a client either gives up or sends
    whatever it has; and a JSON-RPC interface on plain `http` on a host that is not
    loopback or private carries every request, its credential included, in the clear.

    One finding lists every defect, because they are one document's. The card's
    signatures are not verified.
    """

    meta = RuleMeta(
        id="guardana.a2a.agent_card",
        title="A2A agent card is incomplete, or declares what no caller can satisfy",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_ASI07_2026, OWASP_ASI04_2026),
        required_capabilities=frozenset({Capability.INSPECT_A2A}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    @property
    def estimated_requests(self) -> int:
        """The card, and nothing else."""
        return 1

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a card missing a field, a complete one, and one the agent would not serve."""
        return materialise(
            (
                _samples.sample(
                    "a card without a description",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(card=_samples.card(description="")),
                ),
                _samples.sample(
                    "a complete card on https",
                    FixtureOutcome.CLEAN,
                    _samples.target,
                ),
                _samples.sample(
                    "a card answered 403",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(statuses={"card": 403}),
                ),
            )
        )

    def examine(self, view: A2aView) -> Iterator[Finding]:
        """List every defect of the card in one finding, or say why the card was not read."""
        card = view.card
        if card is None:
            yield self.unverified(view, f"the agent card could not be read: {view.card_error}")
            return
        defects = [
            f"it has no {name}"
            for name in _REQUIRED_FIELDS
            if card.get(name) is None or card.get(name) == "" or card.get(name) == []
        ]
        defects.extend(
            f"a security requirement names {name}, which securitySchemes does not declare"
            for name in view.undeclared_schemes
        )
        interface = view.jsonrpc_interface
        if (
            interface is not None
            and urlsplit(interface).scheme == "http"
            and not view.jsonrpc_interface_is_local
        ):
            judged = (
                "not shown to be loopback or private"
                if view.jsonrpc_interface_judged_by_url
                else "that is not loopback or private"
            )
            defects.append(f"its JSON-RPC 1.0 interface is plain http on a host {judged}")
        if defects:
            yield self.finding(view, f"the agent card at {view.card_url}: {'; '.join(defects)}")
