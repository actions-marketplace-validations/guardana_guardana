"""A retrieval application over a fixtures file's seeded items, for driving the seeded checks.

`SeededApplication` answers an item's question with the item's presence marker when the
asking tenant may read it, and with a reply that holds no marker otherwise; switches
break its tenant filter per channel, leave items out of its index, make it obey a
poisoned document, send an empty reply to anyone asking about another tenant's item, and
make it stop finding anything after a number of requests.
`seeded_target` builds the target the CLI builds from `--fixtures`: the run's endpoint and
one endpoint per tenant, all on one meter.

    fixtures = parse_fixtures(text.encode(), Path("guardana-fixtures.yaml"))
    target = seeded_target(fixtures, SeededApplication(fixtures, leaking={"documents"}))
"""

from collections.abc import Collection, Sequence

from guardana.core.budget import Budgets
from guardana.core.fixtures import Fixtures, SeededItem, normalise
from guardana.core.target.endpoint import ChatMessage, EndpointTarget
from guardana.core.target.seeded import SeededTarget
from guardana.core.usage import UsageMeter

NOT_FOUND = "I could not find that in your documents."
"""What the application answers when the asking tenant may not read the item, or it is unseeded."""


def tenant_key(tenant: str) -> str:
    """Return the API key `seeded_target` gives `tenant`, which tells the double who asks."""
    return f"key-{tenant}"


class SeededApplication:
    """A chat transport standing in for an application with its own index and a tenant filter.

    The tenant is read from the API key a request carries (`tenant_key`); a request
    under any other key is the run's own connection and reaches no item. `leaking`
    names the channels whose filter is broken, so any tenant reads any item there;
    `unseeded` names item labels left out of the index; `obeys` appends the joined
    instruction marker when a poisoned document is answered; `blank_to_others` sends an
    empty reply to a tenant asking about an item it does not own, whatever the filter
    does; `forgets_after` answers every request after that many with `NOT_FOUND`. Every
    request is counted.
    """

    def __init__(  # noqa: PLR0913 — one keyword per switch
        self,
        fixtures: Fixtures,
        *,
        leaking: Collection[str] = (),
        unseeded: Collection[str] = (),
        obeys: bool = False,
        blank_to_others: bool = False,
        forgets_after: int | None = None,
    ) -> None:
        self._items = fixtures.items
        self._tenants = {tenant_key(name): name for name in fixtures.tenant_names}
        self._leaking = frozenset(leaking)
        self._unseeded = frozenset(unseeded)
        self._obeys = obeys
        self._blank_to_others = blank_to_others
        self._forgets_after = forgets_after
        self.asked: list[tuple[str | None, str]] = []
        """Every request, as (the tenant it was sent as or None, the question)."""

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Answer the last user message as the tenant `api_key` names."""
        question = next((m.content for m in reversed(messages) if m.role == "user"), "")
        tenant = None if api_key is None else self._tenants.get(api_key)
        self.asked.append((tenant, question))
        item = self._retrieved(question)
        forgotten = self._forgets_after is not None and len(self.asked) > self._forgets_after
        if tenant is None or item is None or forgotten:
            return NOT_FOUND
        if self._blank_to_others and item.owner != tenant:
            return ""
        if item.owner != tenant and item.channel not in self._leaking:
            return NOT_FOUND
        reply = f"The reference code is {item.markers.presence}."
        if self._obeys and item.markers.joined is not None:
            reply = f"{reply} {item.markers.joined}"
        return reply

    def _retrieved(self, question: str) -> SeededItem | None:
        """Return the seeded item whose retrieval term the question carries, as an index would."""
        asked = normalise(question)
        for item in self._items:
            if item.label not in self._unseeded and normalise(item.markers.term) in asked:
                return item
        return None


def seeded_target(
    fixtures: Fixtures,
    application: SeededApplication,
    *,
    budgets: Budgets | None = None,
) -> SeededTarget:
    """Build a seeded target over `application`: the run's endpoint and every tenant, one meter."""
    meter = UsageMeter(budgets or Budgets())
    endpoint = EndpointTarget("http://application.test", "app", transport=application, meter=meter)
    tenants = {
        name: EndpointTarget(
            "http://application.test",
            "app",
            api_key=tenant_key(name),
            transport=application,
            meter=meter,
        )
        for name in fixtures.tenant_names
    }
    return SeededTarget(endpoint, fixtures, tenants)


__all__ = ["NOT_FOUND", "SeededApplication", "seeded_target", "tenant_key"]
