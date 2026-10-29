"""How much a rule is allowed to do, and what a run is willing to permit.

Dynamic security testing has side effects by nature: it sends prompts, and some
checks try to make an agent take an action. That is the point — an agency rule
that never offers a tool proves nothing. But a rule that could delete something
must never run because somebody typed the default command against production, so
every rule declares its impact and a run declares what it permits.
"""

from enum import StrEnum


class Impact(StrEnum):
    """What running a rule does to the world.

    Ordered from least to most consequential, and compared by that order rather
    than by name, so a new level can be inserted without every comparison having
    to be revisited.
    """

    PASSIVE = "passive"
    """Sends nothing: reads files, a trace or a saved run.

    A rule that sends any request to a live target, a manifest read included, is at
    least `ACTIVE`.
    """

    ACTIVE = "active"
    """Sends requests to a live target: prompts to a model, or reads of a server's manifest.

    Costs money or quota and appears in the target's logs.
    """

    SIDE_EFFECTING = "side_effecting"
    """May cause the target to act: call a tool, write to a memory store.

    Simulated by Guardana's own harness today — the tool is a double and nothing
    real happens. It is still declared, because the same rule pointed at a
    customer's harness would drive their tools.
    """


_ORDER = {Impact.PASSIVE: 0, Impact.ACTIVE: 1, Impact.SIDE_EFFECTING: 2}


def permits(allowed: Impact, required: Impact) -> bool:
    """Whether a run allowing `allowed` may run a rule whose impact is `required`."""
    return _ORDER[required] <= _ORDER[allowed]


class Maturity(StrEnum):
    """How much a rule's verdict should be trusted.

    Stated per rule rather than per release, because a package at 1.0 can still
    contain a check nobody has calibrated. A team gating a deployment is entitled
    to know which of the rules blocking them are still finding their feet.
    """

    EXPERIMENTAL = "experimental"
    BETA = "beta"
    STABLE = "stable"


class Detection(StrEnum):
    """What a finding from a rule states about the target: a checked fact, or a lead.

    Defined by the fact a finding states, not by how it was computed. A rule that can
    emit both kinds declares `HEURISTIC`, because a reader cannot tell from one finding
    which kind it is holding.
    """

    INVARIANT = "invariant"
    """Every finding states a checked fact about the target.

    A planted marker seen in output, a byte sequence or opcode present, a server
    answering without credentials, a recorded span showing the forbidden step.
    """

    HEURISTIC = "heuristic"
    """A finding is a lead a person confirms.

    A keyword, a phrase or name list, a threshold, an entropy or pattern match decides
    whether the risk is real.
    """

    UNDECLARED = "undeclared"
    """The rule's author has not said which of the two its findings are."""
