"""The plugin-trust options every discovering command takes, their resolution, and the hint.

Declared once and resolved once: a safe mode spelled differently by each command is
a safe mode somebody sets wrongly, and a refusal that only one command prints is a
refusal the rest hide.
"""

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Annotated

import typer
from guardana.core.entrypoints import InstalledEntryPoint
from guardana.core.plugins import PluginMode, PluginTrust, normalize_distribution
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.report import CheckError

DEFAULT_MODE = PluginMode.BUILTINS
"""The trust a command applies when neither a flag nor the profile states one."""

PluginsOption = Annotated[
    str | None,
    typer.Option(
        "--plugins",
        help="Which installed plugins to load: all|builtins|allowlist|disabled; "
        "default builtins, or the profile's plugins:",
    ),
]
"""`--plugins`; None when not passed, so the profile or the default decides."""

AllowPluginOption = Annotated[
    list[str] | None,
    typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
]
"""`--allow-plugin`, repeatable; meaningful only beside `--plugins allowlist`."""

NoPluginsOption = Annotated[
    bool,
    typer.Option("--no-plugins", help="Deprecated alias for --plugins disabled."),
]
"""`--no-plugins`, kept only on the commands whose pipelines already pass it."""


@dataclass(frozen=True, slots=True)
class ResolvedTrust:
    """The trust a command runs under, and whether anybody stated it."""

    trust: PluginTrust
    stated: bool
    """True when a flag or the profile chose the trust; False for the command default."""


def resolve_trust(
    plugins: str | None,
    allow: Sequence[str] | None,
    profile: Profile | None,
    *,
    no_plugins: bool = False,
) -> ResolvedTrust:
    """Choose the trust from the flags, then the profile's `plugins:`, then `builtins`.

    A flag replaces the profile's trust whole rather than merging with it, so a
    pipeline checking an untrusted contribution narrows trust with one flag whatever
    the profile says. `--no-plugins` means what it always meant, nothing imported.
    """
    allowed = list(allow or ())
    if no_plugins and plugins is not None:
        raise typer.BadParameter("pass either --plugins or the deprecated --no-plugins, not both")
    mode = _mode(plugins) if plugins is not None else None
    if allowed and mode is not PluginMode.ALLOWLIST:
        # Refused rather than ignored: a user who named distributions and got a
        # mode that ignores them would believe they had restricted something.
        raise typer.BadParameter("--allow-plugin only applies with --plugins allowlist")
    if mode is PluginMode.ALLOWLIST and not allowed:
        # An empty allowlist loads exactly what builtins does while reading as a
        # stated, deliberate restriction, which also silences the refusal hint.
        raise typer.BadParameter(
            "--plugins allowlist needs at least one --allow-plugin <distribution>; "
            "for the built-ins alone use --plugins builtins"
        )
    if no_plugins:
        return ResolvedTrust(PluginTrust(mode=PluginMode.DISABLED), stated=True)
    if mode is not None:
        return ResolvedTrust(PluginTrust(mode=mode, allowed=frozenset(allowed)), stated=True)
    if profile is not None and profile.plugins is not None:
        return ResolvedTrust(profile.plugins, stated=True)
    return ResolvedTrust(PluginTrust(mode=DEFAULT_MODE), stated=False)


def _mode(plugins: str) -> PluginMode:
    try:
        return PluginMode(plugins)
    except ValueError as exc:
        raise typer.BadParameter(
            f"unknown plugin mode {plugins!r}; expected one of {[str(m) for m in PluginMode]}"
        ) from exc


def load_failures(registry: Registry) -> tuple[CheckError, ...]:
    """Every load error of `registry` that is not a refusal by plugin trust."""
    return registry.load_failures


def warn_about_load_errors(registry: Registry, resolved: ResolvedTrust, *, what: str) -> None:
    """Print a warning for every entry point `registry` refused or failed to load.

    A check that never loaded looks, in its effect, exactly like one that loaded and
    stayed quiet — unless something says otherwise, in the same place the result
    appears. Under an unstated trust the refusals are left to `hint_refused_plugins`,
    which names them once with the way to admit them. `what` completes "could not
    load ___" in the caller's own vocabulary.
    """
    errors = registry.load_errors if resolved.stated else load_failures(registry)
    for error in errors:
        typer.echo(
            f"warning: could not load {what} — {error.source} ({error.stage}): {error.reason}",
            err=True,
        )


def admission_forms(distributions: Sequence[str]) -> tuple[str, ...]:
    """List the ways to admit `distributions`, narrowest first: flags, profile, `all`.

    An empty sequence leaves only `--plugins all`, the one form that admits an entry
    point which names no distribution.
    """
    forms: list[str] = []
    if distributions:
        flags = " ".join(f"--allow-plugin {name}" for name in distributions)
        forms.append(f"--plugins allowlist {flags}")
        forms.append(
            f"plugins: {{mode: allowlist, allow: [{', '.join(distributions)}]}} "
            f"in guardana.yaml, used with --profile guardana.yaml"
        )
    forms.append("--plugins all, which loads every installed distribution")
    return tuple(forms)


def refused_distributions(refused: Iterable[InstalledEntryPoint]) -> dict[str, int]:
    """Count refused entry points per distribution, as first spelled; unnamed ones excluded."""
    spelled: dict[str, str] = {}
    counts: Counter[str] = Counter()
    for entry_point in refused:
        if entry_point.distribution is None:
            continue
        key = normalize_distribution(entry_point.distribution)
        spelled.setdefault(key, entry_point.distribution)
        counts[key] += 1
    return {spelled[key]: counts[key] for key in spelled}


def hint_refused_plugins(registry: Registry, resolved: ResolvedTrust) -> None:
    """Name what the unstated default refused, and how to admit it, on stderr.

    Printed whatever the gate decides: a team that switched `fail_on_error` off
    would otherwise lose an installed pack without a word. A stated trust is the
    user's own decision and gets only the ordinary load warnings.
    """
    if resolved.stated or not registry.refused:
        return
    named = refused_distributions(registry.refused)
    unnamed = [ep for ep in registry.refused if ep.distribution is None]
    lines = [
        f"warning: plugin trust was not stated, so only Guardana's built-ins were loaded and "
        f"{len(registry.refused)} entry point(s) of installed distributions were refused:"
    ]
    lines.extend(f"  • {name} — {count} entry point(s)" for name, count in named.items())
    lines.extend(
        f"  • {ep.name} (module {ep.module}) — names no distribution, so only --plugins all "
        f"admits it"
        for ep in unnamed
    )
    first, *rest = admission_forms(list(named))
    lines.append(f"  to load them, state the trust, narrowest first: {first}")
    lines.extend(f"    or {form}" for form in rest)
    typer.echo("\n".join(lines), err=True)


__all__ = [
    "DEFAULT_MODE",
    "AllowPluginOption",
    "NoPluginsOption",
    "PluginsOption",
    "ResolvedTrust",
    "admission_forms",
    "hint_refused_plugins",
    "load_failures",
    "refused_distributions",
    "resolve_trust",
    "warn_about_load_errors",
]
