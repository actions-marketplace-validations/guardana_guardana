"""What a run consumed, as the manifest records it.

Field names follow the OpenTelemetry GenAI semantic conventions
(`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`) minus the namespace,
so a team already collecting those does not have to translate ours.

The per-request and per-target shapes live in `guardana.core.usage`, next to the
meter that produces them: a target has to be able to count without importing the
document format its numbers eventually land in.
"""

from collections.abc import Mapping
from dataclasses import dataclass

JUDGE_BLOCKS = ("llm_judge", "guard")
"""The `evaluators:` blocks whose judges meter their own calls, in the order a run lists them."""


@dataclass(frozen=True, slots=True)
class JudgeUsage:
    """What one configured judge spent grading a run, on a meter of its own.

    Read like `TargetUsage`: a null token sum means the judge's provider reported
    none, never that grading was free.
    """

    requests: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests_missing_token_counts: int = 0
    budget_exhausted: bool = False
    """Whether this judge's own ceiling stopped the run, rather than the target's."""

    def __post_init__(self) -> None:
        """Refuse a negative count, which no meter can produce."""
        for name in ("requests", "input_tokens", "output_tokens", "requests_missing_token_counts"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative, got {value}")


@dataclass(frozen=True, slots=True)
class RunUsage:
    """What the whole run spent, as far as anyone could tell.

    Every field defaults to `None`, and that default is the point. A run against
    a target that does not meter itself must not look like a run that cost
    nothing — "nobody counted" and "it was free" are different facts, and only
    one of them lets a team set next month's budget.

    `estimated_cost` stays `None` until a price table exists as profile data.
    Guardana does not ship provider prices: the engine knows no vendor, and an
    invented cost is worse than no cost.
    """

    requests: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests_missing_token_counts: int | None = None
    estimated_cost: float | None = None
    wall_time_seconds: float | None = None
    judge: Mapping[str, JudgeUsage] | None = None
    """What each judge configured under `evaluators:` spent, keyed by its block.

    Kept apart from the target's counts above, which a budget and a collector read as
    the target's bill. `None` means nobody counted judge calls, never that none were made.
    """

    def __post_init__(self) -> None:
        """Refuse a judge block no build meters, or an empty map that would read as counted."""
        if self.judge is None:
            return
        if not self.judge:
            raise ValueError("judge usage is None when nobody counted, never an empty map")
        unknown = sorted(set(self.judge) - set(JUDGE_BLOCKS))
        if unknown:
            raise ValueError(f"judge usage names blocks no judge meters: {unknown}")
