"""The scripted agents the A2A rules sample themselves against, built fresh for each run."""

from collections.abc import Callable, Mapping
from typing import Any

from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome
from guardana.core.target import A2aAgentTarget, Target
from guardana.core.testing.a2a import ScriptedA2aAgent, agent_card

AGENT = "https://agent.invalid/"
"""A name reserved never to resolve, so no sample can reach a real host."""

FIRST = "sample-caller-a"
SECOND = "sample-caller-b"
CALLERS = {FIRST: "alice", SECOND: "bob"}
TASKS = {"alice": ["7c0e9a52-4f1b-4d8e-9a3c-2b6f1e8d4a10"]}


def target(  # noqa: PLR0913 — one keyword per behaviour a sample varies in
    *,
    credential: str | None = FIRST,
    other: str | None = SECOND,
    card: Mapping[str, Any] | None = None,
    enforced: bool = True,
    owner_bound: bool = True,
    errors: Mapping[str, int] | None = None,
    statuses: Mapping[str, int] | None = None,
) -> A2aAgentTarget:
    """Build an agent target over a scripted agent that behaves as the keywords say."""
    scripted = ScriptedA2aAgent(
        AGENT,
        card=card,
        callers=CALLERS,
        tasks=TASKS,
        enforced=enforced,
        owner_bound=owner_bound,
        errors=errors,
        statuses=statuses,
    )
    return A2aAgentTarget(AGENT, credential=credential, other_credential=other, sender=scripted)


def card(**overrides: object) -> dict[str, object]:
    """Build a complete card for the sample agent, with `overrides` applied over it."""
    return {**agent_card(f"{AGENT}a2a"), **overrides}


def sample(name: str, outcome: FixtureOutcome, build: Callable[[], Target]) -> DeclaredFixture:
    """Declare one sample, built afresh each time the rule is verified."""
    return DeclaredFixture(name, outcome, build)
