from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0084_001,
    OWASP_ASI03_2026,
    OWASP_MCP07_2025,
)
from guardana.rules.mcp import _samples
from guardana.rules.mcp._base import McpAuthorizationRule


class McpUnauthenticatedAccessRule(McpAuthorizationRule):
    """An MCP server that hands its tool manifest to a caller presenting nothing.

    Authorization is `OPTIONAL` in MCP, so this is not a specification violation on
    its own — it is a fact about a deployment, and it is the fact every other
    authorization check depends on. A server that asks for nothing cannot
    demonstrate that it validates anything, and its authorization metadata is never
    fetched, which is why the audience, session and metadata checks decline rather
    than pass when this one fires.

    Severity follows reachability. A server on a loopback or private address is how
    everyone develops and is reported `low` with that said out loud; the same
    server on a routable address is publishing an agent's tool surface to anyone
    who asks, and the tool list is itself reconnaissance (`AML.T0084.001`).
    Locality is never decided by a new lookup of the server's name, which the
    server answers itself; when it is unknown, the server is graded as routable.
    """

    meta = RuleMeta(
        id="guardana.mcp.unauthenticated_access",
        title="MCP server answers a tool listing with no credential",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP07_2025, OWASP_ASI03_2026, ATLAS_T0084_001),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    claim = "whether it requires a credential is unknown"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, then a handshake, its notification and a listing, all anonymous."""
        return 4

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a server answering anybody, one refusing them, and one nothing can be read of."""
        return materialise(
            (
                _samples.sample(
                    "a server listing its tools to a caller presenting nothing",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(_samples.open_server()),
                ),
                _samples.sample(
                    "a server refusing its tools to a caller presenting nothing",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.gated_server(), credential=_samples.CREDENTIAL
                    ),
                ),
                _samples.sample(
                    "a server speaking only a revision guardana does not",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_samples.unspoken_server()),
                ),
            )
        )

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Report an anonymous caller receiving the manifest, or why nobody could tell."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if not view.anonymous.open_to_anyone:
            return
        if view.server_is_local:
            yield self.finding(
                view,
                "the server returns its tool manifest to a caller presenting no credential; "
                "it is on a loopback or private address, so the exposure is to whatever "
                "already runs there",
                severity=Severity.LOW,
            )
            return
        yield self.finding(
            view,
            "the server returns its tool manifest to a caller presenting no credential, "
            "on an address that is not loopback or private",
        )
