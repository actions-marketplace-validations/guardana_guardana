"""Wire the judges `guardana.yaml` configures, through the CLI's endpoint seam.

The wiring lives in `guardana.core.evaluator.config`; a command routes each judge's
endpoint through the CLI's transport seam, so the transport its tests substitute reaches
the judges too, whatever provider or adapter a judge block names.
"""

from guardana.cli._connection import endpoint_for
from guardana.cli._endpoint import build_endpoint
from guardana.core.budget import Budgets
from guardana.core.evaluator.config import JudgeMeter, JudgeMeters
from guardana.core.evaluator.config import wire_config_evaluators as _wire
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.target import EndpointTarget
from guardana.core.target.connection import ResolvedConnection


class _JudgeEndpoints:
    """Judge endpoints built through the CLI's transport seam."""

    def __call__(self, url: str, model: str, api_key: str | None) -> EndpointTarget:
        """Build a judge endpoint on the default provider."""
        return build_endpoint(url, model, api_key=api_key)

    def connect(self, connection: ResolvedConnection) -> EndpointTarget:
        """Build the judge endpoint a judge block resolved to, on its provider or adapter."""
        return endpoint_for(connection)


judge_endpoint = _JudgeEndpoints()
"""Build a judge endpoint through the CLI's transport seam."""


def wire_config_evaluators(
    registry: Registry, profile: Profile, budgets: Budgets | None = None, *, sending: bool = True
) -> JudgeMeters:
    """Register the judges `profile` configures, built on the CLI's endpoints.

    `sending` False is for a command that never asks them, such as `plan`: no key
    variable has to be set.
    """
    return _wire(registry, profile, budgets, build=judge_endpoint, sending=sending)


__all__ = ["JudgeMeter", "JudgeMeters", "judge_endpoint", "wire_config_evaluators"]
