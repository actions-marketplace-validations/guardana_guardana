from dataclasses import dataclass
from enum import StrEnum


class ShortfallKind(StrEnum):
    """Why a run did not get the coverage its verdict would need.

    Some kinds are a demand somebody wrote and did not get; others are coverage no run
    can do without, such as a target with nothing in it. Every member means the same
    thing to a gate — this run is not entitled to a verdict — and differs in what the
    operator has to change, which is the only thing they can act on.
    """

    MISSING_DIMENSION = "missing_dimension"
    """Evidence a policy or a contract required, which this producer does not record."""

    CONTRACT_NOT_APPLICABLE = "contract_not_applicable"
    """Contracts were loaded and not one of them was about this execution."""

    UNEXAMINED_COMPONENT = "unexamined_component"
    """A model component the run observed and no rule that completed read."""

    INCOMPLETE_RECORDING = "incomplete_recording"
    """A graded recording whose origin run stopped before every reply was received."""

    DEMANDED_CHECK = "demanded_check"
    """A check the run was required to complete that was skipped, errored or never reached."""

    SEED_NOT_REACHED = "seed_not_reached"
    """A seeded item whose control did not return its marker in any trial, for one tenant.

    The item was not reachable, or the asking tenant's connection does not reach its own
    data the same way, so a reply without another tenant's marker proves nothing.
    """

    EMPTY_TARGET = "empty_target"
    """A file target whose scope holds no file to scan beside its ignore files.

    A scan that read nothing found nothing, which is not the same as finding the target
    clean; the path or the excludes that removed every file is what to check.
    """

    UNGRADED_CASES = "ungraded_cases"
    """A rule that attempted cases and graded too few of them to establish anything.

    None graded at all under every policy, or a share below the policy's
    `min_graded_share` floor: every case declined or undecidable leaves the check
    unanswered, whatever `fail_on_inconclusive` says.
    """


@dataclass(frozen=True, slots=True)
class CoverageShortfall:
    """Coverage the verdict needed and this run did not get.

    Deliberately not a `CheckError` and deliberately not a `SkippedRule`.

    Not an error: an error means a check malfunctioned, and a framework that does
    not emit approval spans has malfunctioned in no way at all. It is also a
    *toggle* — `fail_on_error` — and the whole point of this channel is that it
    has none.

    Not a skip: a skip already says "this rule did not run, here is the capability
    it needed", and `fail_on_skipped` defaults to off because most skips are
    ordinary. Recording the same fact twice would let the two disagree, and the
    disagreement would be a rule that is skipped *and* reported clean.

    What it is, is coverage the verdict needed coming back unmet: most often the
    operator's own demand — they wrote `trace.require`, or an assertion, and the
    evidence to settle it was never recorded — and sometimes coverage no run can do
    without, such as a target with no file in it. That makes the run `indeterminate`
    with nothing to switch off.
    """

    kind: ShortfallKind
    name: str
    """What went uncovered: a required dimension, an inapplicable contract, a rule, a target."""

    detail: str
    """One sentence for whoever has to fix it — which file asked, and what is missing."""
