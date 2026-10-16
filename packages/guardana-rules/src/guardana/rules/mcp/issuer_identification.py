from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind, display_url
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP01_2025, OWASP_MCP07_2025
from guardana.rules.mcp import _samples
from guardana.rules.mcp._base import McpAuthorizationRule, further_issuers

_ISS_SUPPORTED = "authorization_response_iss_parameter_supported"


class McpIssuerIdentificationRule(McpAuthorizationRule):
    """An authorization server that leaves its clients unable to detect a mix-up.

    > MCP clients **MUST** apply the validation in RFC 9207 Section 2.4 before
    > transmitting the authorization code to any token endpoint.

    That obligation is a client's, and a client is what Guardana is — so the check
    is on the other half of it. An authorization server that returns the `iss`
    parameter **MUST** advertise `authorization_response_iss_parameter_supported`
    in its metadata, and one that advertises nothing gives a client no way to tell
    whether an authorization response came back from the server it started the flow
    with. Only the first authorization server the resource names is fetched, so the rule
    declines for every further one rather than pass what it never read.

    That is the mix-up attack. A client talking to two authorization servers — one
    of them attacker-influenced — can be walked into redeeming a code at the wrong
    one, and `iss` is the only signal the protocol offers to catch it. Where it is
    not advertised, `2026-07-28` tells a client to proceed, so the absence is not
    something a careful client can compensate for.

    Reported `medium`, deliberately between the two arguments. It is a `SHOULD` on
    the authorization server, which argues for less; it disables a client `MUST`,
    which argues for more; and the attack needs a second authorization server in the
    picture, which is why it is not `high`. The specification says a later revision
    is expected to raise the server-side requirement to `MUST` — this rule is what
    will already be measuring when it does.
    """

    meta = RuleMeta(
        id="guardana.mcp.issuer_identification",
        title="Authorization server gives an MCP client no way to detect an issuer mix-up",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP01_2025, OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    claim = "whether its clients can detect an issuer mix-up was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous three, then six documented metadata attempts."""
        return 10

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample metadata silent about `iss`, metadata advertising it, and two left unread."""
        silent = {
            key: value
            for key, value in _samples.AUTHORIZATION_METADATA.items()
            if key != _ISS_SUPPORTED
        }
        return materialise(
            (
                _samples.sample(
                    "authorization server metadata not advertising the iss parameter",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(
                        _samples.protected_server(authorization_metadata=silent),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "authorization server metadata advertising the iss parameter",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.protected_server(), credential=_samples.CREDENTIAL
                    ),
                ),
                _samples.sample(
                    "an authorization server publishing no metadata to read",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.protected_server(authorization_metadata=None),
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
        """Read the authorization server's metadata and grade what it says about `iss`."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            yield self.metadata_not_fetched(view)
            return
        document = view.authorization_server
        if document is None or not document.readable:
            # Silence would read as "this server advertises `iss` correctly".
            # `guardana.mcp.authorization_discovery` reports *why* the document is
            # missing, under a different rule id a profile may have excluded.
            yield self.unverified(
                view,
                "no authorization server metadata could be read, so whether a client can "
                "detect an issuer mix-up here was never seen; "
                "guardana.mcp.authorization_discovery reports why the document is missing",
            )
            return
        if (document.content or {}).get(_ISS_SUPPORTED) is not True:
            yield self.finding(
                view,
                f"the authorization server metadata at {display_url(document.url)} does not "
                f"advertise '{_ISS_SUPPORTED}', so a client redeeming an authorization code here "
                f"cannot tell that the response came from the issuer it started the flow with "
                f"(RFC 9207)",
            )
        further = further_issuers(view)
        if further:
            named = ", ".join(display_url(issuer) for issuer in further)
            yield self.unverified(
                view,
                f"the protected resource metadata names further authorization servers "
                f"({named}) whose metadata this run did not fetch, so whether they "
                f"advertise '{_ISS_SUPPORTED}' was never seen",
            )
