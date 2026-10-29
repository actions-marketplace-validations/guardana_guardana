"""`guardana doctor` — what this installation is, and what is wrong with it.

The command somebody runs when a scan behaved unexpectedly, and the one a support
conversation should start with. It answers questions that are otherwise guessed
at: which distributions are installed and at what versions, which plugins were
discovered and which failed to import, whether the profile parses, and whether any
setting weakens the gate in a way the user may not have intended.

It never contacts a target. Diagnosing an installation must not cost money or
appear in somebody's production logs.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    ResolvedTrust,
    admission_forms,
    load_failures,
    refused_distributions,
    resolve_trust,
)
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._profile_files import read_profile_files
from guardana.cli.exit_codes import ExitCode
from guardana.core.entrypoints import (
    GROUPS,
    OUTPUT_GROUPS,
    RENDERER_GROUP,
    REPORTER_GROUP,
    InstalledEntryPoint,
    installed_entry_points,
)
from guardana.core.output import output_collisions, unselectable_reason
from guardana.core.plugins import (
    BUILTIN_DISTRIBUTIONS,
    PluginMode,
    PluginTrust,
    normalize_distribution,
)
from guardana.core.profile import Profile
from guardana.core.redaction import EvidenceMode
from guardana.core.registry import Registry
from guardana.core.report import CheckError

_DISTRIBUTIONS = ("guardana-core", "guardana-rules", "guardana-cli", "guardana-report")


class Level(StrEnum):
    """How much a diagnostic matters."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


_MARK = {Level.OK: "✓", Level.WARN: "!", Level.FAIL: "✖"}

_BUILTINS = frozenset(normalize_distribution(name) for name in BUILTIN_DISTRIBUTIONS)
_WIDENING = frozenset({PluginMode.ALL, PluginMode.ALLOWLIST})


@dataclass(frozen=True, slots=True)
class Check:
    """One thing doctor looked at."""

    name: str
    level: Level
    detail: str


def _versions() -> list[Check]:
    """Report each distribution's version, and flag a mismatch.

    A mismatch is a real failure mode rather than a tidiness concern: a stale
    `guardana-rules` beside a current CLI is a different tool than the version
    string suggests, and it is invisible until a rule behaves unexpectedly.
    """
    found: dict[str, str] = {}
    checks: list[Check] = []
    for name in _DISTRIBUTIONS:
        try:
            found[name] = version(name)
        except PackageNotFoundError:
            checks.append(Check(name, Level.WARN, "not installed"))
    checks.extend(Check(name, Level.OK, found_version) for name, found_version in found.items())
    distinct = set(found.values())
    if len(distinct) > 1:
        checks.append(
            Check(
                "version consistency",
                Level.WARN,
                f"distributions are at different versions ({', '.join(sorted(distinct))}) — "
                f"a rule may behave differently from what the CLI version suggests",
            )
        )
    return checks


def _plugins(registry: Registry, failures: Sequence[CheckError]) -> list[Check]:
    """Report what discovery registered, and every load failure no pack block reports."""
    checks: list[Check] = []
    rules = registry.rules()
    checks.append(Check("rules discovered", Level.OK if rules else Level.FAIL, str(len(rules))))
    checks.append(Check("evaluators discovered", Level.OK, str(len(registry.evaluators()))))
    schemes = registry.schemes()
    checks.append(
        Check(
            "target schemes",
            Level.OK,
            ", ".join(schemes) if schemes else "none (installed targets are Python-only)",
        )
    )
    checks.extend(
        Check(f"plugin {error.source}", Level.FAIL, f"did not load ({error.stage}): {error.reason}")
        for error in failures
    )
    third_party = sorted({rule.meta.id.split(".", 1)[0] for rule in rules} - {"guardana"})
    if third_party:
        checks.append(
            Check(
                "third-party rules",
                Level.WARN,
                f"rules from {', '.join(third_party)} are installed and will run — "
                f"a plugin is code this process imports (see SECURITY.md)",
            )
        )
    return checks


class _State(StrEnum):
    """What this run did with one installed entry point, or what selecting an output would do."""

    LOADED = "loaded"
    REFUSED = "refused"
    FAILED = "failed to import"
    ON_SELECTION = "imported only when selected"
    REFUSED_OUTPUT = "refused if selected"
    UNSELECTABLE = "never selectable"


_RUN_STATES = (_State.LOADED, _State.REFUSED, _State.FAILED)
_OUTPUT_STATES = (_State.ON_SELECTION, _State.REFUSED_OUTPUT, _State.UNSELECTABLE)
_NOUN = {RENDERER_GROUP: "format", REPORTER_GROUP: "reporter"}


@dataclass(frozen=True, slots=True)
class _Seen:
    """One third-party entry point and what this run did with it."""

    entry_point: InstalledEntryPoint
    state: _State
    reason: str = ""

    @property
    def shown(self) -> str:
        """The state as the entry point's line prints it."""
        if not self.reason:
            return str(self.state)
        if self.state is _State.FAILED:
            return f"{self.state} ({self.reason})"
        if self.state is _State.UNSELECTABLE:
            return f"{self.state}: {self.reason}"
        return f"{self.state} {self.reason}"


def _is_builtin(entry_point: InstalledEntryPoint) -> bool:
    return (
        entry_point.distribution is not None
        and normalize_distribution(entry_point.distribution) in _BUILTINS
    )


def _classify(
    registry: Registry, third_party: Sequence[InstalledEntryPoint]
) -> tuple[list[_Seen], list[CheckError]]:
    """Pair each third-party entry point with its outcome in `registry`.

    Returns the pairs and the load failures left over, which no pack block reports.
    State is read from what discovery recorded against each entry point, never
    re-decided from the trust or matched by name, so what doctor calls refused or
    failed is exactly what the run refused or failed to import.
    """
    refused = set(registry.refused)
    failed = dict(registry.failed)
    seen: list[_Seen] = []
    for entry_point in third_party:
        if entry_point in refused:
            seen.append(_Seen(entry_point, _State.REFUSED))
        elif entry_point in failed:
            seen.append(_Seen(entry_point, _State.FAILED, failed[entry_point].reason))
        else:
            seen.append(_Seen(entry_point, _State.LOADED))
    reported = [failed[item.entry_point] for item in seen if item.state is _State.FAILED]
    leftover = [
        error
        for error in load_failures(registry)
        if not any(error is attributed for attributed in reported)
    ]
    return seen, leftover


def _classify_outputs(
    third_party: Sequence[InstalledEntryPoint],
    every_output: Sequence[InstalledEntryPoint],
    trust: PluginTrust,
) -> list[_Seen]:
    """Say what selecting each third-party output would do, from metadata and trust alone.

    The registry never sees an output, so nothing it recorded applies. The checks run
    in the order selection refuses in: the name, then a collision, then trust.
    """
    colliding = {
        (collision.group, collision.name): collision
        for collision in output_collisions(every_output)
    }
    seen: list[_Seen] = []
    for entry_point in third_party:
        unselectable = unselectable_reason(entry_point.group, entry_point.name)
        collision = colliding.get((entry_point.group, entry_point.name))
        if unselectable is not None:
            seen.append(_Seen(entry_point, _State.UNSELECTABLE, unselectable))
        elif collision is not None:
            reason = f"name installed by {len(collision.entry_points)} distributions"
            seen.append(_Seen(entry_point, _State.UNSELECTABLE, reason))
        elif trust.allows(entry_point.distribution):
            seen.append(_Seen(entry_point, _State.ON_SELECTION))
        else:
            reason = f"under plugin trust {trust.describe()}"
            seen.append(_Seen(entry_point, _State.REFUSED_OUTPUT, reason))
    return seen


def _collisions(every_output: Sequence[InstalledEntryPoint]) -> list[Check]:
    """One warning per output name that more than one distribution installs."""
    return [
        Check(
            "output collision",
            Level.WARN,
            f"the {_NOUN[collision.group]} {collision.name} is installed by "
            f"{len(collision.entry_points)} distributions "
            f"({', '.join(collision.distributions)}); selecting it is refused",
        )
        for collision in output_collisions(every_output)
    ]


def _normalized(distribution: str | None) -> str | None:
    return normalize_distribution(distribution) if distribution else None


def _by_distribution(seen: Sequence[_Seen]) -> dict[str | None, list[_Seen]]:
    """Group entry points by normalised distribution name, None for the unnamed."""
    groups: dict[str | None, list[_Seen]] = {}
    for item in seen:
        groups.setdefault(_normalized(item.entry_point.distribution), []).append(item)
    return groups


def _pack_check(items: Sequence[_Seen]) -> Check:
    """One block for one distribution: a heading line, then a line per entry point."""
    first = items[0].entry_point
    if first.distribution is None:
        name = "pack from an unknown distribution"
    else:
        name = f"pack {first.distribution} {first.version or '(version unknown)'}"
    counts = Counter(item.state for item in items)
    if counts[_State.FAILED]:
        level = Level.FAIL
    elif counts[_State.REFUSED] or counts[_State.UNSELECTABLE]:
        level = Level.WARN
    else:
        level = Level.OK
    headings = [
        _heading(noun, counts, states)
        for noun, states in (
            ("Guardana entry point(s)", _RUN_STATES),
            ("output entry point(s)", _OUTPUT_STATES),
        )
        if any(counts[state] for state in states)
    ]
    lines = ["; ".join(headings)]
    for item in items:
        entry_point = item.entry_point
        lines.append(
            f"    {entry_point.group} {entry_point.name} → module {entry_point.module}: "
            f"{item.shown}"
        )
    return Check(name, level, "\n".join(lines))


def _heading(noun: str, counts: Counter[_State], states: Sequence[_State]) -> str:
    total = sum(counts[state] for state in states)
    summary = ", ".join(f"{counts[state]} {state}" for state in states if counts[state])
    return f"{total} {noun} — {summary}"


def _consequence(registry: Registry, profile: Profile) -> Check:
    """Say what the refusals mean for the gate under `profile`, and how to lift them."""
    if profile.policy.fail_on.fail_on_error:
        effect = (
            "with this profile (fail_on_error on), scan and probe exit 2, and monitor "
            "alerts every cycle, while these stay refused"
        )
    else:
        effect = (
            "with this profile (fail_on_error off), the checks from these packs simply do not run"
        )
    first, *rest = admission_forms(list(refused_distributions(registry.refused)))
    lines = [f"{effect}; to load them, narrowest first: {first}"]
    lines.extend(f"    or {form}" for form in rest)
    return Check("refused packs", Level.WARN, "\n".join(lines))


def _installed_packs(
    registry: Registry,
    installed: Sequence[InstalledEntryPoint],
    profile: Profile,
    trust: PluginTrust,
) -> tuple[list[Check], list[CheckError]]:
    """Report what each installed third-party pack would execute, and what this run did.

    Listed from distribution metadata, which imports nothing; only discovery under
    the resolved trust imported anything, and discovery never imports an output.
    "Guardana entry points" is the claim, not "third-party code": dependencies and
    `.pth` hooks run before any trust decision.
    """
    every_output = [entry_point for entry_point in installed if entry_point.group in OUTPUT_GROUPS]
    third_party = [entry_point for entry_point in installed if not _is_builtin(entry_point)]
    ran, leftover = _classify(
        registry, [entry_point for entry_point in third_party if entry_point.group in GROUPS]
    )
    outputs = _classify_outputs(
        [entry_point for entry_point in third_party if entry_point.group in OUTPUT_GROUPS],
        every_output,
        trust,
    )
    seen = [*ran, *outputs]
    if not seen:
        builtins = len(installed) - len(third_party)
        return [
            Check(
                "installed packs",
                Level.OK,
                f"no third-party Guardana entry points are installed; "
                f"{builtins} built-in Guardana entry point(s)",
            )
        ], leftover
    checks = [_pack_check(items) for items in _by_distribution(seen).values()]
    checks.extend(_collisions(every_output))
    if any(item.state is _State.REFUSED for item in ran):
        checks.append(_consequence(registry, profile))
    return checks, leftover


def _trust(
    registry: Registry, resolved: ResolvedTrust, installed: Sequence[InstalledEntryPoint]
) -> Check:
    """Name the trust in force, and say when it kept Guardana's own entry points out."""
    stated = "stated" if resolved.stated else "not stated, the default"
    builtins_refused = sum(1 for entry_point in registry.refused if _is_builtin(entry_point))
    if builtins_refused:
        return Check(
            "plugin trust",
            Level.WARN,
            f"{resolved.trust.describe()} ({stated}) — {builtins_refused} of "
            f"{sum(1 for ep in installed if _is_builtin(ep))} "
            f"built-in Guardana entry point(s) refused",
        )
    return Check("plugin trust", Level.OK, f"{resolved.trust.describe()} ({stated})")


def _profile_trust(profile: Profile) -> list[Check]:
    """Warn when the profile widens trust, since only a flag can narrow it again."""
    trust = profile.plugins
    if trust is None or trust.mode not in _WIDENING:
        return []
    return [
        Check(
            "profile plugins",
            Level.WARN,
            f"{trust.describe()} widens trust beyond Guardana's built-ins — a pipeline "
            f"checking untrusted contributions should pass --plugins builtins as a flag, "
            f"which outranks the profile",
        )
    ]


def _allowed_plugins(
    resolved: ResolvedTrust, installed: Sequence[InstalledEntryPoint]
) -> list[Check]:
    """Warn about each allowlisted distribution that would load nothing.

    An allowlist entry that is not installed, or installs no Guardana entry point,
    leaves its pack's checks absent with nothing said; a team expecting them would
    read the quieter report as a cleaner one.
    """
    trust = resolved.trust
    if trust.mode is not PluginMode.ALLOWLIST:
        return []
    advertising = {_normalized(entry_point.distribution) for entry_point in installed}
    checks: list[Check] = []
    for name in sorted(trust.allowed):
        if not _is_installed(name):
            detail = "not installed, so nothing from it is loaded"
        elif normalize_distribution(name) not in advertising:
            detail = "installed, and registers no Guardana entry point, so nothing is loaded"
        else:
            continue
        checks.append(Check(f"plugins.allow {name}", Level.WARN, detail))
    return checks


def _is_installed(name: str) -> bool:
    try:
        distribution(name)
    except PackageNotFoundError:
        return False
    return True


def _profile_files(profile: Profile, registry: Registry) -> list[Check]:
    """Fail on each contract, calibration or rule the profile names and a run refuses."""
    return [
        Check("profile files", Level.FAIL, problem)
        for problem in read_profile_files(profile, registry).problems
    ]


def _policy(profile: Profile) -> list[Check]:
    """Flag settings that weaken the gate, whether or not that was intended.

    Reported as warnings, never as failures: each of these is a legitimate choice
    somebody may have made deliberately. What must not happen is making it
    silently — a gate you think you configured and did not is worse than no gate.
    """
    checks: list[Check] = [Check("profile", Level.OK, f"{profile.name} parsed")]
    fail_on = profile.policy.fail_on
    if not fail_on.fail_on_error:
        checks.append(
            Check(
                "fail_on_error",
                Level.WARN,
                "off — a check that could not run will not fail the build",
            )
        )
    if profile.policy.exclude:
        checks.append(
            Check(
                "rules.exclude",
                Level.WARN,
                f"{len(profile.policy.exclude)} pattern(s) exclude rules: "
                f"{', '.join(profile.policy.exclude)}",
            )
        )
    if profile.privacy.mode is EvidenceMode.FULL:
        checks.append(
            Check(
                "evidence_mode",
                Level.WARN,
                "full — model output is stored in reports (secrets are still removed)",
            )
        )
    if profile.allow_destructive:
        checks.append(Check("allow_destructive", Level.WARN, "on — destructive rules may run"))
    if profile.budgets.is_unbounded:
        checks.append(
            Check(
                "budgets",
                Level.WARN,
                "no ceiling set — a probe against a paid endpoint has no upper bound",
            )
        )
    return checks


def doctor(
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
) -> None:
    """Report what this installation is and what is wrong with it. Contacts nothing."""
    prof = resolve_profile(profile, preset)
    resolved = resolve_trust(plugins, allow_plugin, prof)
    registry = Registry.discover(resolved.trust)
    everything = installed_entry_points(groups=(*GROUPS, *OUTPUT_GROUPS))
    installed = [entry_point for entry_point in everything if entry_point.group in GROUPS]
    packs, leftover = _installed_packs(registry, everything, prof, resolved.trust)
    checks = [
        *_versions(),
        _trust(registry, resolved, installed),
        *_plugins(registry, leftover),
        *packs,
        *_policy(prof),
        *_profile_files(prof, registry),
        *_profile_trust(prof),
        *_allowed_plugins(resolved, everything),
    ]
    for check in checks:
        typer.echo(f"{_MARK[check.level]} {check.name}: {check.detail}")
    failures = [c for c in checks if c.level is Level.FAIL]
    warnings = [c for c in checks if c.level is Level.WARN]
    typer.echo("")
    typer.echo(f"{len(failures)} problem(s), {len(warnings)} thing(s) worth knowing.")
    if failures:
        # Something here is broken rather than merely unusual, so the command that
        # exists to find that says so in its exit status too.
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
