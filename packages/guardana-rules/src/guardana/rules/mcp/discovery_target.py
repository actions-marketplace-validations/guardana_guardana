from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind, display_url
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM02_2026, OWASP_MCP01_2025
from guardana.rules.mcp import _samples
from guardana.rules.mcp._base import McpAuthorizationRule


class McpDiscoveryTargetRule(McpAuthorizationRule):
    """An MCP server that points its client at an address a client must not follow.

    Authorization discovery is the one place in MCP where the server chooses a URL
    and the client fetches it, which makes it a server-side request forgery
    primitive aimed at whoever is running the client. The specification names the
    destinations: cloud metadata at `169.254.169.254`, where a fetch returns
    credentials; internal services on a loopback port; `javascript:` and `file:`
    schemes, where a URL is opened rather than fetched; and plain `http://` for an
    authorization endpoint that **MUST** be served over HTTPS.

    The check and the guard are the same code path, and that is the point. Guardana
    refuses to fetch such an address, and **the refusal is the finding** — a
    scanner that followed the URL to prove it was dangerous would have performed
    the attack in order to report it, which is the confused deputy this whole area
    is about.

    The cloud metadata addresses, link-local, multicast and reserved ranges are
    refused however local the server under test is. Every other address that is not
    globally routable — loopback, private, shared and carrier-grade ranges alike —
    is refused only when the server under test is not itself local. A development
    server on `127.0.0.1` pointing at an authorization server on `127.0.0.1` is a
    normal setup, and reporting it would make this rule noise on the first machine
    anybody tries it on.

    Every authorization server the resource document names is held to the guard; only
    the first one's metadata is fetched, so the rule declines while another one passed
    the guard unread. A protected resource document that came back but could not be read,
    or whose address answered an error other than `404` or `410`, hides the authorization
    server it names, so the rule declines there. One that was never published names nothing,
    and leaves nothing unseen. A server that answered an anonymous caller is never
    asked for discovery at all, so the rule declines there too.
    """

    meta = RuleMeta(
        id="guardana.mcp.discovery_target",
        title="MCP server directs its client to an address a client must not follow",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP01_2025, OWASP_LLM02_2026, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    claim = "the addresses it directs a client to were never seen"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous three, then six documented metadata attempts."""
        return 10

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a challenge naming cloud metadata, a conforming chain, and four left unread."""
        return materialise(
            (
                _samples.sample(
                    "a challenge directing the client to the cloud metadata address",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(
                        _samples.protected_server(
                            challenge=(
                                f'Bearer resource_metadata="{_samples.UNSAFE_ADDRESS}'
                                f'/.well-known/oauth-protected-resource"'
                            )
                        ),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "a discovery chain naming only the server's own origin",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.protected_server(), credential=_samples.CREDENTIAL
                    ),
                ),
                _samples.sample(
                    "a server speaking only a revision guardana does not",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_samples.unspoken_server()),
                ),
                _samples.sample(
                    "protected resource metadata served as a page that is not JSON",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.protected_server(resource_metadata_body=b"<html>sign in</html>"),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "protected resource metadata answering 503",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.protected_server(resource_metadata_status=503),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "a server answering an anonymous caller",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_samples.open_server()),
                ),
            )
        )

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Report every discovery address this run refused to fetch, and why."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            yield self.metadata_not_fetched(view)
            return
        for document in view.refused_addresses:
            address = display_url(document.url)
            yield self.finding(
                view,
                f"the server directed this client to {address} during authorization "
                f"discovery, which was not fetched because {document.refused}",
            )
        if view.unread_issuers:
            named = ", ".join(display_url(issuer) for issuer in view.unread_issuers)
            yield self.unverified(
                view,
                f"the protected resource metadata names further authorization servers "
                f"({named}) whose metadata this run did not fetch, so the addresses they "
                f"direct a client to were never seen",
            )
        resource = view.protected_resource
        if resource is not None and resource.error is not None:
            # The resource document names the authorization server, so one that came
            # back unread hides the next address; one that was never published hides none.
            yield self.unverified(
                view,
                f"the protected resource metadata at {display_url(resource.url)} could not "
                f"be read ({resource.error}), so the authorization server it directs a client "
                f"to was never seen",
            )
