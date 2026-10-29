from collections.abc import Callable

import typer
from guardana.core.evaluator.config import unusable_url
from guardana.core.target import ChatTransport, EndpointTarget
from guardana.core.usage import UsageMeter

transport_factory: Callable[[], ChatTransport] | None = None
"""The single transport seam: when set, its product backs every endpoint the CLI builds.

Tests substitute a fake transport here; production leaves it None so `EndpointTarget`
uses its real network transport.
"""


def build_endpoint(  # noqa: PLR0913 — each is a distinct endpoint config knob, keyword-only
    url: str,
    model: str,
    *,
    api_key: str | None = None,
    system_prompt: str | None = None,
    provider: str = "openai",
    transport: ChatTransport | None = None,
    meter: UsageMeter | None = None,
) -> EndpointTarget:
    """Construct an `EndpointTarget` from loose fields, through the CLI's transport seam.

    An endpoint a resolved connection names is built by `endpoint_for` instead. An
    explicit `transport` wins; otherwise `seam_transport` refuses an unusable URL and
    supplies the test seam's transport, if one is set.
    """
    if transport is None:
        transport = seam_transport(url)
    return EndpointTarget(
        url,
        model,
        api_key=api_key,
        system_prompt=system_prompt,
        provider=provider,
        transport=transport,
        meter=meter,
    )


def seam_transport(url: str) -> ChatTransport | None:
    """Refuse a URL the built-in transports cannot use, then return the test seam's transport.

    None means no seam is set, so the endpoint builds its provider's network transport.
    The refusal comes first so a test sees the one a user would.
    """
    problem = unusable_url(url)
    if problem is not None:
        raise typer.BadParameter(f"the endpoint URL {problem}", param_hint="'--url'")
    return None if transport_factory is None else transport_factory()


__all__ = ["build_endpoint", "seam_transport", "transport_factory", "unusable_url"]
