"""The internal seam through which a target learns which rule is asking."""

from typing import Protocol, runtime_checkable

from guardana.core.target.base import Target


@runtime_checkable
class RuleScoped(Protocol):
    """A target that hands each rule its own view of itself.

    The runner calls `for_rule` once per rule inside `_execute_one`, so a target that
    records or replays exchanges attributes each one to the rule that sent it without
    ambient state shared between rules.
    """

    def for_rule(self, rule_id: str) -> Target:
        """Return a view of this target that attributes every exchange to `rule_id`."""
        raise NotImplementedError
