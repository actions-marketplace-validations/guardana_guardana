"""Running the rule set against a live A2A agent.

The agent is examined through the verifier like any target; what is particular is
reading two callers' credentials from the environment and refusing a pair that
cannot tell two callers apart.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass

import typer
from guardana.cli._errors import EndpointFlag, remedies_for
from guardana.cli._evaluators import judge_endpoint
from guardana.core.calibration.store import RecordedCalibration
from guardana.core.manifest import DeploymentRef, RunSource
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.runner import DEFAULT_ENDPOINT_CONCURRENCY
from guardana.core.target import A2aAgentTarget, private_url_parts
from guardana.core.target.a2a import CARD_OR_ORIGIN, names_card_or_origin
from guardana.core.verify import Verification, Verifier

_HTTP_PREFIXES = ("http://", "https://")
_ACCEPTED_FLAGS = (EndpointFlag.A2A_TOKEN_ENV, EndpointFlag.CONCURRENCY)


@dataclass(frozen=True, slots=True)
class A2aConnection:
    """How to reach the A2A agent under test, and as which two callers."""

    address: str
    credential: str | None = None
    """The first caller's bearer token, read from the environment and never from an argument."""

    other_credential: str | None = None
    """The second caller's bearer token; it must belong to a different caller than the first."""


def connection_from(
    address: str, token_env: str | None, other_token_env: str | None
) -> A2aConnection:
    """Read both callers' tokens from the environment, refusing a pair that cannot be used.

    The second variable alone, or two variables holding the same value, would make the
    cross-caller check ask one caller about its own tasks and call that a leak.
    """
    refuse_address(address)
    if other_token_env is not None and token_env is None:
        raise typer.BadParameter(
            "--a2a-other-token-env names the second caller, who asks for the first "
            "caller's tasks; pass --a2a-token-env for the first caller too"
        )
    credential = _token(token_env, "--a2a-token-env")
    other = _token(other_token_env, "--a2a-other-token-env")
    if other is not None and other == credential:
        raise typer.BadParameter(
            f"{token_env} and {other_token_env} hold the same value, so both callers are "
            f"one caller; give the second caller a credential of its own"
        )
    return A2aConnection(address, credential=credential, other_credential=other)


def refuse_address(address: str) -> None:
    """Refuse an address that is not http(s), names neither card nor origin, or has userinfo."""
    if not address.startswith(_HTTP_PREFIXES):
        raise typer.BadParameter("the A2A agent needs an http or https URL", param_hint="'--a2a'")
    if not names_card_or_origin(address):
        raise typer.BadParameter(CARD_OR_ORIGIN, param_hint="'--a2a'")
    if "userinfo" in private_url_parts(address):
        raise typer.BadParameter(
            "the A2A agent URL carries userinfo, which cannot be sent; pass bearer tokens "
            "through --a2a-token-env instead",
            param_hint="'--a2a'",
        )


def plan_target(address: str) -> A2aAgentTarget:
    """Build a target for pricing an agent, without contacting it and without a credential."""
    refuse_address(address)
    return A2aAgentTarget(address)


def build_a2a_target(connection: A2aConnection) -> A2aAgentTarget:
    """Build the target the probe examines."""
    return A2aAgentTarget(
        connection.address,
        credential=connection.credential,
        other_credential=connection.other_credential,
    )


def run_a2a_probe(  # noqa: PLR0913 — a connection and the run's facts
    registry: Registry,
    profile: Profile,
    connection: A2aConnection,
    *,
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    calibrations: Mapping[str, RecordedCalibration] | None = None,
    source: RunSource | None = None,
    deployment: DeploymentRef | None = None,
) -> Verification:
    """Examine the agent through the verifier; a refused credential names `--a2a-token-env`."""
    target = build_a2a_target(connection)
    verifier = Verifier(
        trust=registry.trust or PluginTrust(mode=PluginMode.BUILTINS),
        profile=profile,
        registry=registry,
        calibrations=calibrations,
        concurrency=concurrency,
        judge_endpoint=judge_endpoint,
        remedies=remedies_for(_ACCEPTED_FLAGS),
    )
    return verifier.run(target, source=source, deployment=deployment)


def _token(variable: str | None, flag: str) -> str | None:
    """Read one bearer token, refusing a variable name that holds nothing."""
    if variable is None:
        return None
    value = os.environ.get(variable)
    if not value:
        raise typer.BadParameter(
            f"{flag} names {variable!r}, which is unset or empty in this environment; "
            f"export it, or drop the flag and accept that the checks needing it will "
            f"report inconclusive"
        )
    return value


__all__ = [
    "A2aConnection",
    "build_a2a_target",
    "connection_from",
    "plan_target",
    "refuse_address",
    "run_a2a_probe",
]
