from collections.abc import Callable, Collection, Iterable
from enum import StrEnum
from typing import TypeVar
from urllib.error import URLError

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.evaluator.config import JudgeUnavailableError, safe_url
from guardana.core.monitor import TargetStoppedError
from guardana.core.redaction import MessageQuoting, RedactionPolicy
from guardana.core.target import EndpointError, display_url
from guardana.core.target.failure import FailureRemedies, describe_failure, http_status_problem
from guardana.core.verify import Verification

T = TypeVar("T")


class EndpointFlag(StrEnum):
    """A flag that some endpoint command offers as a remedy for a failed request."""

    ADAPTER = "--adapter"
    API_KEY_ENV = "--api-key-env"
    CONCURRENCY = "--concurrency"
    MCP_TOKEN_ENV = "--mcp-token-env"  # noqa: S105 — a flag name, not a credential
    A2A_TOKEN_ENV = "--a2a-token-env"  # noqa: S105 — a flag name, not a credential


_TOKEN_FLAGS = (EndpointFlag.MCP_TOKEN_ENV, EndpointFlag.A2A_TOKEN_ENV)


def _auth_advice(accepts: Collection[EndpointFlag]) -> str:
    """Spell the auth remedies for a rejected request, naming only accepted flags."""
    tokens = [flag for flag in _TOKEN_FLAGS if flag in accepts]
    if tokens:
        return f" ({' or '.join(tokens)} names the variable holding the bearer token)"
    knobs = [flag for flag in (EndpointFlag.ADAPTER, EndpointFlag.API_KEY_ENV) if flag in accepts]
    if knobs == [EndpointFlag.ADAPTER, EndpointFlag.API_KEY_ENV]:
        return " (an --adapter's headers, or --api-key-env)"
    if knobs == [EndpointFlag.ADAPTER]:
        return " (an --adapter's headers)"
    if knobs == [EndpointFlag.API_KEY_ENV]:
        return " (--api-key-env names the variable holding the key)"
    return ""


def _rate_limit_advice(accepts: Collection[EndpointFlag]) -> str:
    """Spell the remedies for a sustained rate limit, naming only accepted flags."""
    if EndpointFlag.CONCURRENCY in accepts:
        return "lower --concurrency, or wait for the quota to reset"
    return "wait for the quota to reset"


def remedies_for(accepts: Collection[EndpointFlag]) -> FailureRemedies:
    """Return the remedies a failure message gives, naming only the flags in `accepts`."""
    return FailureRemedies(
        auth=f"check the auth header / body{_auth_advice(accepts)}",
        rate_limited=_rate_limit_advice(accepts),
    )


def report_target_stop(verification: Verification) -> None:
    """Say on stderr what the target did when it stopped the run `verification` holds.

    The run is saved and gated as any other; this names the cause the exit code `4` stands for.
    """
    for message in verification.stop_messages:
        typer.echo(f"error: {message}", err=True)


def run_judged(action: Callable[[], T]) -> T:
    """Run `action`, ending a run whose configured judge failed with exit `4`, in the judge's words.

    For a target that reports its own failures inside the run, such as an MCP server, the
    judge is the one connection whose failure still ends it.
    """
    try:
        return action()
    except JudgeUnavailableError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc


def run_against_endpoint(
    url: str,
    action: Callable[[], T],
    *,
    privacy: RedactionPolicy,
    secrets: Iterable[str] = (),
    accepts: Collection[EndpointFlag] = (),
) -> T:
    """Run `action`, turning endpoint connection/response failures into a clean CLI error.

    Catches network failures (`URLError`/`OSError`) and malformed responses
    (`EndpointError`), prints a one-line message to stderr, and exits with
    `TARGET_UNAVAILABLE` — the user's environment, kept apart from the gate's
    "ran, found blocking issues" and from our own defects. An error status is
    reported distinctly from an unreachable host: 401, 403 and 407 point at the
    credentials, and any other status quotes the start of the response body,
    because that is where the endpoint says what it refused. What is quoted follows
    `privacy`, the run's own policy, and never holds one of `secrets`, the values the
    run authenticates with; under `metadata_only` only the body's size is given. A judge's
    failure keeps the same exit code and is reported in its own words, never as
    the target's, and so is a monitor cycle its target stopped, in the words the run
    recorded. A run its target stopped part-way is not raised here: it is returned,
    saved, and named by `report_target_stop`.

    `accepts` is the set of flags the calling command actually takes; the message
    names no other one, because advice that the command would reject costs the
    reader a second failed run. `url` is shown without its userinfo, query or fragment.
    """
    shown = display_url(url)
    quoting = MessageQuoting.of(privacy, secrets)
    try:
        return run_judged(action)
    except TargetStoppedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc
    except (URLError, OSError, EndpointError) as exc:
        said = describe_failure(exc, shown, quoting, remedies_for(accepts))
        typer.echo(f"error: {said}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc


__all__ = [
    "EndpointFlag",
    "JudgeUnavailableError",
    "http_status_problem",
    "remedies_for",
    "report_target_stop",
    "run_against_endpoint",
    "run_judged",
    "safe_url",
]
