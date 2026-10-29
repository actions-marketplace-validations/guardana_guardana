from urllib.parse import urlsplit

from guardana.core.budget import Budgets
from guardana.core.target._a2a_view import (
    A2aAnonymous,
    A2aAnswer,
    A2aCallers,
    A2aReply,
    A2aSecurity,
    A2aView,
    observe,
)
from guardana.core.target._mcp_http import HttpSender, Sender
from guardana.core.target._url import display_url
from guardana.core.target.base import Capability, Target, TargetKind, WireProtocol
from guardana.core.usage import TargetUsage, UsageMeter

__all__ = [
    "CARD_OR_ORIGIN",
    "A2aAgentTarget",
    "A2aAnonymous",
    "A2aAnswer",
    "A2aCallers",
    "A2aReply",
    "A2aSecurity",
    "A2aView",
    "names_card_or_origin",
]

_SCHEMES = frozenset({"http", "https"})

CARD_OR_ORIGIN = (
    "the A2A agent URL has a path that is not an agent card: pass the agent card's URL "
    "(ending in .json) or the agent's origin"
)
"""Why an agent URL is refused when it names neither a card nor an origin."""


def names_card_or_origin(url: str) -> bool:
    """Whether `url` names an agent card (a path ending in `.json`) or an origin (no path).

    Any other path would be replaced by the origin's well-known card, which describes
    whatever agent the origin serves at its root rather than the one the path named.
    """
    path = urlsplit(url).path
    return path in ("", "/") or path.endswith(".json")


class A2aAgentTarget(Target):
    """A live A2A v1 agent under test: its card, and whether it tells one caller from another.

    Only reads are sent — the card, `GetTask`, `ListTasks` and the extended card — and
    only to the origin the operator named, so a credential never leaves it. `credential`
    is the first caller's bearer token and `other_credential` the second's; with both,
    the second caller asks for the first caller's tasks. Every request goes through
    `sender`, the built-in pinned client unless a test double is given.

    Kind is `endpoint`, it speaks A2A and the one capability is `INSPECT_A2A`, so every
    chat and MCP rule is skipped as not applicable. What an answer means is the rules'
    business.
    """

    kind = TargetKind.ENDPOINT

    def __init__(
        self,
        url: str,
        *,
        credential: str | None = None,
        other_credential: str | None = None,
        sender: Sender | None = None,
    ) -> None:
        if urlsplit(url).scheme not in _SCHEMES or not urlsplit(url).hostname:
            raise ValueError("an A2A agent URL needs an http or https scheme and a host")
        if not names_card_or_origin(url):
            raise ValueError(CARD_OR_ORIGIN)
        if other_credential is not None and credential is None:
            raise ValueError(
                "a second caller's credential needs the first caller's: the second caller "
                "asks for tasks the first caller listed"
            )
        if other_credential is not None and other_credential == credential:
            raise ValueError(
                "the two credentials are the same, so both callers are one caller and every "
                "task would read as visible across them"
            )
        self._url = url
        self._credential = credential
        self._other_credential = other_credential
        self._meter = UsageMeter()
        self._view, self._probe = observe(
            url,
            credential=credential,
            other_credential=other_credential,
            meter=self._meter,
            send=sender if sender is not None else HttpSender(),
        )

    def capabilities(self) -> set[Capability]:
        """Declare A2A inspection, and nothing a chat or MCP rule could ask for."""
        return {Capability.INSPECT_A2A}

    def speaks(self) -> frozenset[WireProtocol]:
        """Speak A2A."""
        return frozenset({WireProtocol.A2A})

    @property
    def ref(self) -> str:
        """The agent under test, as it appears in findings."""
        return display_url(self._url)

    def a2a(self) -> A2aView:
        """Return what this run observed about the agent, each section bought on first read."""
        return self._view

    def sent_secrets(self) -> tuple[str, ...]:
        """Return both credentials and every task id the agent revealed during the run.

        A task id names something a caller owns, so a saved run quotes none: an agent
        that echoes one into an error has it withheld like a credential.
        """
        sent = tuple(c for c in (self._credential, self._other_credential) if c is not None)
        return (*sent, *self._probe.learned())

    def usage(self) -> TargetUsage:
        """Return what this agent has been asked for, the card included."""
        return self._meter.snapshot()

    def apply_budgets(self, budgets: Budgets) -> None:
        """Adopt the run's ceilings; every request this target makes counts against them."""
        self._meter.apply(budgets)

    def protocols(self) -> dict[str, str]:
        """Report A2A 1.0 once the agent answered a result or an A2A-defined error; else nothing."""
        return {"a2a": "1.0"} if self._probe.spoke_a2a else {}
