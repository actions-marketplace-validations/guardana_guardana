"""Every Guardana entry point installed on this system, listed without importing any of them.

One enumeration, walked by every consumer that decides trust: `Registry.discover`,
output selection, `doctor`, the pack commands and anything that reports what an
installed pack would execute. A second walk would be a second answer to "what is
installed", and the day the two disagree is the day an entry point listed as refused
is imported anyway.

There are six groups. The four in `GROUPS` are walked by every run; the two in
`OUTPUT_GROUPS` are walked only by output selection, `doctor` and the pack commands,
so an installed output a run does not select is never imported.

Reading `importlib.metadata` imports nothing; only `InstalledEntryPoint.load` does.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points

TAXONOMY_GROUP = "guardana.taxonomies"
RULE_GROUP = "guardana.rules"
EVALUATOR_GROUP = "guardana.evaluators"
TARGET_GROUP = "guardana.targets"
RENDERER_GROUP = "guardana.renderers"
REPORTER_GROUP = "guardana.reporters"

GROUPS = (TAXONOMY_GROUP, RULE_GROUP, EVALUATOR_GROUP, TARGET_GROUP)
"""The four entry-point groups every run discovers, in the order discovery loads them.

Taxonomies first: a rule can only name a framework that is already registered. The
two output groups are not here: `Registry.discover` never walks them.
"""

OUTPUT_GROUPS = (RENDERER_GROUP, REPORTER_GROUP)
"""The two entry-point groups of installed outputs, walked only by selection, `doctor`
and the pack commands, never by a run that does not select an output."""


@dataclass(frozen=True, slots=True)
class InstalledEntryPoint:
    """One advertised entry point, and the distribution that advertised it."""

    group: str
    name: str
    value: str
    """The `module:attr` reference as written in the distribution's metadata."""

    module: str
    """The module `load()` imports: the part of `value` before the colon."""

    distribution: str | None
    """The distribution's name as spelled in its metadata; None when it cannot say.

    An entry point with no distribution is treated as third-party by every trust
    mode that is not `all`, so this is never guessed from the module name.
    """

    version: str | None
    entry_point: EntryPoint = field(compare=False, repr=False)
    """The `importlib.metadata` handle `load()` goes through."""

    def load(self) -> object:
        """Import the module and return the object this entry point names."""
        return self.entry_point.load()


def installed_entry_points(groups: Sequence[str] = GROUPS) -> tuple[InstalledEntryPoint, ...]:
    """List every entry point of `groups`, group by group in the order given, importing none.

    The default is the four groups every run discovers; a caller that needs the output
    groups names them.
    """
    return tuple(
        _record(group, entry_point) for group in groups for entry_point in entry_points(group=group)
    )


def _record(group: str, entry_point: EntryPoint) -> InstalledEntryPoint:
    dist = entry_point.dist
    name = getattr(dist, "name", None)
    version = getattr(dist, "version", None)
    return InstalledEntryPoint(
        group=group,
        name=entry_point.name,
        value=entry_point.value,
        module=entry_point.value.split(":", 1)[0].strip(),
        distribution=str(name) if name else None,
        version=str(version) if version else None,
        entry_point=entry_point,
    )
