from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar
from urllib.error import URLError
from urllib.parse import parse_qsl, urlsplit

import typer
from guardana.cli._plugins import admission_forms, refused_distributions
from guardana.cli.exit_codes import ExitCode
from guardana.core.redaction import EvidenceMode, MessageQuoting, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.target import EndpointError, LocatorError, Target, TargetKind, display_url
from guardana.core.target.failure import FailureRemedies, describe_failure


def target_options(values: Sequence[str]) -> dict[str, str]:
    """Parse repeatable ``key=value`` target options, refusing ambiguity."""
    parsed: dict[str, str] = {}
    for value in values:
        key, separator, option = value.partition("=")
        key = key.strip()
        if not separator or not key:
            raise typer.BadParameter(
                f"invalid --target-option {value!r}: use a non-empty key=value pair"
            )
        if key in parsed:
            raise typer.BadParameter(
                f"--target-option {key!r} was passed more than once; one target "
                "configuration cannot contain two values for the same key"
            )
        parsed[key] = option
    return parsed


_Fallback = TypeVar("_Fallback")


def resolve_target(
    registry: Registry,
    *,
    locator: str | None,
    options: Sequence[str],
    kind: TargetKind,
    fallback: Callable[[], _Fallback],
) -> Target | _Fallback:
    """Build a selected plugin target, or the command's unchanged built-in target.

    The command chooses ``kind``. A locator can choose an implementation, never
    turn ``scan`` into a network probe or ``probe`` into a file reader.
    """
    if locator is None:
        if options:
            raise typer.BadParameter("--target-option needs --target scheme://locator")
        return fallback()

    scheme, separator, rest = locator.partition("://")
    if not separator or not scheme or not rest:
        raise typer.BadParameter(f"invalid target locator {_shown(locator)!r}: use scheme://value")
    target_type = registry.target_for(scheme)
    if target_type is None:
        available = ", ".join(registry.schemes()) or "none"
        trust = _trust_note(registry)
        raise typer.BadParameter(
            f"unknown target scheme {scheme!r}; loaded schemes: {available}{trust}"
        )
    named = target_options(options)
    try:
        target = target_type.from_locator(rest, options=named)
    except LocatorError as exc:
        raise typer.BadParameter(f"invalid {scheme} target: {exc}") from exc
    except (URLError, OSError, EndpointError) as exc:
        said = describe_failure(
            exc, _shown(locator), _unbuilt_quoting(rest, named), FailureRemedies()
        )
        typer.echo(f"error: {said}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc
    if target.kind is not kind:
        raise typer.BadParameter(
            f"target {_shown(locator)!r} built a {target.kind} target, but this command accepts "
            f"only {kind} targets"
        )
    return target


def _unbuilt_quoting(rest: str, options: Mapping[str, str]) -> MessageQuoting:
    """How to quote a failure of a target that was never built, so declared no secret.

    Every option value and every part of the locator that is not shown is withheld,
    since any of them may be a credential, and the rest is redacted.
    """
    parts = urlsplit(f"https://{rest}")
    hidden = [parts.password or "", parts.query, parts.fragment]
    hidden.extend(value for _name, value in parse_qsl(parts.query, keep_blank_values=True))
    return MessageQuoting.of(
        RedactionPolicy(mode=EvidenceMode.REDACTED), (*options.values(), *hidden)
    )


def _shown(locator: str) -> str:
    """Return `locator` as it may be printed: no userinfo, no fragment, a placeholder query.

    `display_url` does this only for http(s), because a plugin owns the meaning of its
    own scheme's ref. A message is not a ref, so here every scheme is read as a URL.
    """
    scheme, separator, rest = locator.partition("://")
    shown = display_url(f"https://{rest if separator else locator}")
    body = shown.removeprefix("https://")
    if body == shown:
        return shown
    return f"{scheme}://{body}" if separator else body


def _trust_note(registry: Registry) -> str:
    """Explain when a scheme may be absent because plugin trust refused its provider."""
    if not registry.refused:
        return ""
    named = refused_distributions(registry.refused)
    origins = ", ".join(named) if named else "no named distribution"
    forms = "; or ".join(admission_forms(list(named)))
    return (
        f"; plugin trust refused {len(registry.refused)} entry point(s) from {origins}, "
        f"so a scheme they provide is not loaded — admit them with {forms}"
    )


__all__ = ["resolve_target", "target_options"]
