"""The run's endpoint together with the items a fixtures file seeded and one endpoint per tenant.

Every other rule talks to the run's own endpoint, which is never a tenant; a rule that
needs `Capability.SEEDED_DATA` asks through a tenant's endpoint instead, so Guardana
knows which tenant it sent as. Every tenant endpoint bills the run's meter, so the
run's budgets bound all of them.
"""

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from guardana.core.budget import Budgets
from guardana.core.target.base import Capability, Target, TargetKind, WireProtocol
from guardana.core.target.endpoint import (
    ChatMessage,
    EndpointTarget,
    ToolCallReply,
    ToolSpec,
)
from guardana.core.usage import TargetUsage

if TYPE_CHECKING:
    from guardana.core.fixtures import Fixtures
    from guardana.core.keeping import ExchangeKeeper


class SeededTarget(Target):
    """A live endpoint whose own index and doubles hold a fixtures file's seeded items.

    `endpoint` is the run's connection: chat, tool offers, planted canaries and kept
    exchanges all go through it, exactly as without fixtures. `tenants` maps every
    tenant the fixtures declare to an endpoint of its own on the same meter. Tenant
    endpoints keep no exchanges, so what a rule asks as a tenant is never promoted into a
    regression case.
    """

    kind = TargetKind.ENDPOINT

    def __init__(
        self,
        endpoint: EndpointTarget,
        fixtures: "Fixtures",
        tenants: Mapping[str, EndpointTarget],
    ) -> None:
        declared = set(fixtures.tenant_names)
        if set(tenants) != declared:
            raise ValueError(
                f"a seeded target needs one endpoint for each declared tenant "
                f"({', '.join(sorted(declared))}), got {', '.join(sorted(tenants)) or 'none'}"
            )
        for name, tenant in tenants.items():
            if tenant is endpoint:
                raise ValueError(
                    f"tenant {name} is the run's own endpoint; the run's connection is never "
                    f"a tenant, and asking through it would keep a tenant's exchanges"
                )
            if tenant.meter is not endpoint.meter:
                raise ValueError(
                    f"tenant {name}'s endpoint bills another meter than the run's, so the "
                    f"run's budgets would not bound what is asked as {name}"
                )
        self._endpoint = endpoint
        self._fixtures = fixtures
        self._tenants = dict(tenants)

    @property
    def endpoint(self) -> EndpointTarget:
        """The run's own endpoint, which every rule but the seeded ones talks to."""
        return self._endpoint

    @property
    def fixtures(self) -> "Fixtures":
        """The fixtures file the items were seeded from."""
        return self._fixtures

    @property
    def model(self) -> str:
        """The model under test, as the run's endpoint names it."""
        return self._endpoint.model

    @property
    def ref(self) -> str:
        """The run's endpoint: tenants reach the same application, so they share its reference."""
        return self._endpoint.ref

    def sent_secrets(self) -> tuple[str, ...]:
        """Return what the run's endpoint and every tenant's endpoint send to authenticate."""
        return tuple(
            value
            for endpoint in (self._endpoint, *self._tenants.values())
            for value in endpoint.sent_secrets()
        )

    def capabilities(self) -> set[Capability]:
        """Declare what the run's endpoint declares, plus `SEEDED_DATA`."""
        return {*self._endpoint.capabilities(), Capability.SEEDED_DATA}

    def speaks(self) -> frozenset[WireProtocol]:
        """Speak what the run's endpoint speaks."""
        return self._endpoint.speaks()

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        """Send `messages` through the run's own endpoint."""
        return self._endpoint.chat(messages)

    def offer_tools(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSpec]
    ) -> ToolCallReply:
        """Offer `tools` through the run's own endpoint."""
        return self._endpoint.offer_tools(messages, tools)

    def ask_as(self, tenant: str, question: str) -> str:
        """Ask `question` through `tenant`'s endpoint; raise when no reply text arrives."""
        try:
            endpoint = self._tenants[tenant]
        except KeyError:
            raise ValueError(f"{tenant!r} is not a tenant the fixtures declare") from None
        return endpoint.chat([ChatMessage(role="user", content=question)])

    def planting(self, system_prompt: str) -> EndpointTarget:
        """Return the run's endpoint with `system_prompt` planted, on the same meter.

        A canary rule needs no seeded data, so its view is the plain endpoint.
        """
        return self._endpoint.planting(system_prompt)

    def for_rule(self, rule_id: str) -> "SeededTarget":
        """Return the view `rule_id` runs against: the endpoint's view, the same tenants."""
        view = self._endpoint.for_rule(rule_id)
        if view is self._endpoint:
            return self
        return SeededTarget(view, self._fixtures, self._tenants)

    def keep_exchanges(self, keeper: "ExchangeKeeper") -> None:
        """Keep the exchanges rules complete through the run's endpoint; tenants keep none."""
        self._endpoint.keep_exchanges(keeper)

    def stop_keeping(self) -> None:
        """Detach the run's endpoint from its keeper."""
        self._endpoint.stop_keeping()

    def apply_budgets(self, budgets: Budgets) -> None:
        """Adopt `budgets` on the shared meter, refused when any endpoint cannot enforce them."""
        self._endpoint.apply_budgets(budgets)
        for tenant in self._tenants.values():
            tenant.apply_budgets(budgets)

    def usage(self) -> TargetUsage:
        """Return what the run's meter counted: the endpoint and every tenant together."""
        return self._endpoint.usage()


__all__ = ["SeededTarget"]
