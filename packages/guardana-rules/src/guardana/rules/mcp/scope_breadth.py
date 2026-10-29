from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    McpAuthorizationView,
    TargetKind,
    challenge_parameters,
    display_url,
    scopes_in,
)
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM03_2026, OWASP_MCP02_2025
from guardana.rules.mcp import _samples
from guardana.rules.mcp._base import McpAuthorizationRule

# Straight from the specification's own list of common mistakes: "Using wildcard or
# omnibus scopes (`*`, `all`, `full-access`)". Matched exactly rather than by
# substring, because `files:read-all` is a perfectly ordinary scope name.
_OMNIBUS = frozenset({"*", "all", "any", "full", "full-access", "full_access", "everything"})


class McpScopeBreadthRule(McpAuthorizationRule):
    """An MCP server whose advertised scopes cannot express least privilege.

    A token minted against `*` has a blast radius equal to the whole server, and
    revoking it costs the user every workflow at once. The specification lists
    exactly this under scope minimisation, alongside publishing the entire scope
    catalogue in `scopes_supported` rather than the minimum a client needs to
    start.

    Also graded: a `401` that carries no `scope` parameter. The specification says a
    server **SHOULD** name the scopes a request needs, and without it a general
    purpose client has nothing to ask for but everything — which is how a consent
    screen ends up listing permissions nobody wanted and users learn to approve
    without reading. Reported at `low`, because a `SHOULD` is not a `MUST`.

    Scopes are graded across both metadata documents. When the resource document
    names an authorization server whose metadata went unread, the half that was
    read is graded and the rule declines on the other, naming it.
    """

    meta = RuleMeta(
        id="guardana.mcp.scope_breadth",
        title="MCP server advertises scopes that cannot express least privilege",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP02_2025, OWASP_LLM03_2026, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
        detection=Detection.HEURISTIC,
    )

    claim = "the breadth of the scopes it advertises was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous three, then six documented metadata attempts."""
        return 10

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a wildcard scope, narrow scopes, and three servers whose scopes went unread."""
        wildcard = {**_samples.RESOURCE_METADATA, "scopes_supported": ["*"]}
        return materialise(
            (
                _samples.sample(
                    "protected resource metadata advertising a wildcard scope",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(
                        _samples.protected_server(resource_metadata=wildcard),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "narrow scopes advertised and named in the challenge",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.protected_server(), credential=_samples.CREDENTIAL
                    ),
                ),
                _samples.sample(
                    "a gated server publishing neither metadata document",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.protected_server(
                            resource_metadata=None, authorization_metadata=None
                        ),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "an authorization server answering 503 at its metadata addresses",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.protected_server(authorization_metadata_status=503),
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
        """Read the advertised scopes from both metadata documents and the challenge."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        if view.anonymous.open_to_anyone:
            yield self.metadata_not_fetched(view)
            return
        read = 0
        for document, where in (
            (view.protected_resource, "protected resource metadata"),
            (view.authorization_server, "authorization server metadata"),
        ):
            if document is None or not document.readable:
                continue
            read += 1
            omnibus = sorted(s for s in scopes_in(document.content) if _is_omnibus(s))
            if omnibus:
                yield self.finding(
                    view,
                    f"the {where} advertises {omnibus}, a scope that grants everything at "
                    f"once; a token minted against it cannot be reduced and cannot be "
                    f"revoked without revoking every workflow",
                )
        if read == 0:
            # Silence from a rule means the invariant held, so a rule that read no
            # scopes at all must not fall into it: "this server's scopes are narrow"
            # and "nobody ever saw this server's scopes" are different answers, and
            # `authorization_discovery` reporting the missing document is a
            # different rule id that a profile may have excluded.
            yield self.unverified(
                view,
                "no metadata document could be read, so the scopes this server advertises "
                "were never seen; guardana.mcp.authorization_discovery reports why the "
                "surface could not be fetched",
            )
        else:
            unseen = _unseen_authorization_server(view)
            if unseen is not None:
                yield self.unverified(
                    view,
                    f"{unseen}, so only the protected resource metadata's scopes were graded "
                    f"and the scopes the authorization server advertises were never seen",
                )
        yield from self._challenge(view)

    def _challenge(self, view: McpAuthorizationView) -> Iterator[Finding]:
        challenge = view.anonymous.challenge
        if not challenge or "scope" in challenge_parameters(challenge):
            return
        yield self.finding(
            view,
            "the authorization challenge names no 'scope', so a client has no way to ask "
            "for the permissions this request needs and will ask for all of them",
            severity=Severity.LOW,
        )


def _unseen_authorization_server(view: McpAuthorizationView) -> str | None:
    """Say why the authorization server's metadata went unread, or None when nothing is unseen.

    An authorization server that publishes no metadata advertises no scopes, so a
    `404` or `410` leaves nothing unseen; any other error status leaves the document
    unread. No document beside a named issuer means every address for it was refused
    as unsafe to fetch.
    """
    document = view.authorization_server
    if document is not None:
        if document.error is None:
            return None
        return (
            f"the authorization server metadata at {display_url(document.url)} could not be "
            f"read ({document.error})"
        )
    resource = view.protected_resource
    named = resource.content.get("authorization_servers") if resource and resource.content else None
    if not isinstance(named, list):
        return None
    issuer = next((entry for entry in named if isinstance(entry, str) and entry), None)
    if issuer is None:
        return None
    return (
        f"every address for the authorization server metadata of {display_url(issuer)} "
        f"was refused as unsafe to fetch"
    )


def _is_omnibus(scope: str) -> bool:
    return scope.lower() in _OMNIBUS or "*" in scope
