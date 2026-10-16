from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path

from guardana.core.budget import Budgets
from guardana.core.plugins import PluginTrust
from guardana.core.redaction import OMITTED_WHEN_DEFAULT, RedactionPolicy
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.trace.model import Dimension


@dataclass(frozen=True, slots=True)
class FailOn:
    """The bar a finding must clear to fail the build."""

    severity: Severity = Severity.HIGH
    min_confidence: float = 0.0
    fail_on_inconclusive: bool = False
    # Defaults to True where `fail_on_inconclusive` defaults to False, because the
    # two are not the same thing. `inconclusive` is a verdict — the check ran and
    # honestly said "I cannot tell", and you cannot gate on that. An error is a
    # defect: the check did not run, while the result looks as though it did.
    fail_on_error: bool = True
    fail_on_skipped: bool = False
    """Whether a rule the target could not satisfy makes the run indeterminate.

    Off by default, because most skips are ordinary — a file rule against an
    endpoint, a tool-calling rule against a model nobody claimed could call tools.
    On, it says "I am paying for this coverage and I want to know when I did not
    get it", which is the setting a team uses once they have decided what their
    provider must support.
    """

    min_graded_share: float | None = field(default=None, metadata={OMITTED_WHEN_DEFAULT: True})
    """The least share of a rule's attempted cases it must grade, in `(0, 1]`; None for none.

    Checked per rule after the run, never over the whole run: a rule graded nowhere would
    otherwise hide behind one graded everywhere. A rule below it is a coverage shortfall.
    """

    def __post_init__(self) -> None:
        """Refuse a bar `guardana.yaml` would refuse, so code cannot build a gate that never fails.

        NaN or an out-of-range number passes every comparison it is used in the wrong way:
        no confidence is `>=` NaN, so every graded failure would fall under the bar.
        """
        if not isinstance(self.severity, Severity):
            raise TypeError(f"fail_on.severity must be a Severity, got {self.severity!r}")
        confidence = self.min_confidence
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int | float)
            or not 0.0 <= confidence <= 1.0
        ):
            raise ValueError(f"fail_on.min_confidence must be in [0.0, 1.0], got {confidence!r}")
        share = self.min_graded_share
        if share is not None and (
            isinstance(share, bool) or not isinstance(share, int | float) or not 0.0 < share <= 1.0
        ):
            raise ValueError(f"fail_on.min_graded_share must be in (0, 1], got {share!r}")


@dataclass(frozen=True, slots=True)
class Policy:
    """Which rules run, and which findings fail the build."""

    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    fail_on: FailOn = field(default_factory=FailOn)

    def matches(self, rule_id: str) -> bool:
        """Whether a rule id survives the include/exclude globs (exclude wins)."""
        included = any(fnmatch(rule_id, pat) for pat in self.include)
        excluded = any(fnmatch(rule_id, pat) for pat in self.exclude)
        return included and not excluded


@dataclass(frozen=True, slots=True)
class Profile:
    """A `guardana.yaml`, parsed: the policy plus any rule/evaluator configuration."""

    name: str
    policy: Policy
    rule_config: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    evaluator_config: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    rule_paths: tuple[str, ...] = ()
    path_excludes: tuple[str, ...] = ()
    budgets: Budgets = field(default_factory=Budgets)
    max_impact: Impact = Impact.ACTIVE
    """How far this run permits a rule to reach.

    `ACTIVE` by default: sending prompts is what a probe is for, and defaulting to
    `PASSIVE` would make the ordinary command do nothing. Side-effecting rules are
    opt-in because making an agent *act* is a different decision from talking to
    it, and `guardana scan` never reaches either — a file scan is passive whatever
    this says.
    """

    allow_destructive: bool = False
    """Whether a rule that can destroy something may run.

    A separate switch, not a fourth impact level, so raising the impact ceiling
    can never reach it by accident. Nothing shipped is destructive today; the
    switch exists so that a third-party rule which is has somewhere to declare it
    and something to be stopped by.
    """

    privacy: RedactionPolicy = field(default_factory=RedactionPolicy)
    """What evidence this run may keep. See `guardana.core.redaction`.

    A `Profile` built in code defaults to `full`, matching what the engine did
    before the redactor existed; `guardana.yaml` and every CLI command default to
    `redacted`. The difference is deliberate: a library caller has already decided
    what to do with the objects it is handed, while a command writes files.
    """

    required_dimensions: tuple[Dimension, ...] = ()
    """Trace evidence this run demands, from `trace.require:` and from any contract.

    Two sources, one set, because they are the same statement: *I am gating on this
    coverage.* A dimension in here that the producer does not record makes the run
    `indeterminate` with no `fail_on_*` in the path — see `guardana.core.gate`.

    Empty by default, and it only ever governs a trace. Demanding that a *file scan*
    record approvals would be a category error, and reading it as one would turn a
    shared `guardana.yaml` into a `guardana scan` that can never pass.
    """

    calibration_paths: tuple[str, ...] = ()
    """Recorded evaluator calibrations, from `calibrations:` in `guardana.yaml`.

    A run that grades with a measured judge carries the measurement into its own
    evidence, so a reader can see how honest that confidence was and when it was
    checked. Absent, every evaluator is recorded uncalibrated — which is the honest
    answer and was, until this existed, the only one available.
    """

    trials: int = 1
    """How many independent attempts a probe makes at each case, from `trials:`.

    1 in every preset, so no existing gate changes what it costs without an edit.
    Applies only to rules whose verdict depends on a model sampling a reply; a rule
    that does not repeat records one attempt whatever this says.
    """

    contract_paths: tuple[str, ...] = ()
    """Security contracts this profile loads, from `contracts:` in `guardana.yaml`.

    Beside `rule_paths` and read the same way, so a team that keeps one config for a
    pipeline does not have to repeat `--contract` in every job.
    """

    plugins: PluginTrust | None = None
    """Which installed distributions' entry points this profile trusts, from `plugins:`.

    None when the profile does not say, and then whoever discovers decides: the
    library loads everything, a command applies its own default. A stated trust is
    honoured wherever this profile drives discovery.
    """

    delivery_required: bool = False
    """Whether every delivery the run makes must be acknowledged, from `delivery.required`.

    Not part of the verdict: a command decides the exit after the gate, so the digest
    leaves it out and no run record moves when it is set.
    """

    source: Path | None = None
    """The `guardana.yaml` this profile was read from; None for a preset or one built in code.

    Relative entries in `rules.paths`, `contracts:` and `calibrations:` are read beside
    this file, and a command names it when an entry only exists somewhere else.
    """

    def demanding(self, dimensions: Iterable[Dimension]) -> "Profile":
        """Return this profile with `dimensions` added to what the run demands.

        How a loaded contract's implicit requirements join the operator's explicit
        ones without either side having to know about the other. De-duplicated and
        order-preserving, so the shortfall a report prints reads in the order it was
        asked for rather than in whatever order a set happened to iterate.
        """
        merged = dict.fromkeys((*self.required_dimensions, *dimensions))
        return replace(self, required_dimensions=tuple(merged))
