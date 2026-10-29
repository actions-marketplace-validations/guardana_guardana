"""Shared fixtures for the MCP authorization rules.

Addresses are IP literals on purpose. A hostname would make every one of these
tests resolve a name — the guard that decides whether an address is inside the
scanner's own network has to look one up — and a unit test that needs DNS is a
unit test that fails on a machine without it.
"""

from collections.abc import Mapping

from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import McpError, McpServerTarget
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.testing import ScriptedMcpServer

ROUTABLE = "https://93.184.215.14/mcp"
LOOPBACK = "http://127.0.0.1:3000/mcp"
ELSEWHERE = "https://1.2.3.4"
CREDENTIAL = "operator-supplied-token"
TOOLS = [{"name": "read_file", "description": "Read a file from the workspace."}]

CONFORMING_RESOURCE = {
    "resource": "https://93.184.215.14",
    "authorization_servers": ["https://93.184.215.14"],
    "scopes_supported": ["tools:read", "tools:write"],
}
CONFORMING_AUTHORIZATION = {
    "issuer": "https://93.184.215.14",
    "code_challenge_methods_supported": ["S256"],
    "scopes_supported": ["tools:read"],
}
CHALLENGE = (
    'Bearer resource_metadata="https://93.184.215.14/.well-known/oauth-protected-resource", '
    'scope="tools:read"'
)


def guarded(**overrides: object) -> ScriptedMcpServer:
    """A server that refuses an anonymous caller and publishes a conforming surface."""
    settings: dict[str, object] = {
        "tools": TOOLS,
        "credential": CREDENTIAL,
        "challenge": CHALLENGE,
        "resource_metadata": CONFORMING_RESOURCE,
        "authorization_metadata": CONFORMING_AUTHORIZATION,
        "session_ids": [
            "7f3a1c04-1b2d-4e5f-8a9b-0c1d2e3f4a5b",
            "b19e2d55-6c7f-4a01-9d3e-2f8b7c6a5d40",
            "c4f83a01-5e9d-4b72-8f16-3a0c9e7d1b28",
        ],
    }
    settings.update(overrides)
    return ScriptedMcpServer(ROUTABLE, **settings)  # type: ignore[arg-type]


def wide_open(url: str = ROUTABLE, **overrides: object) -> ScriptedMcpServer:
    """A server that answers anybody, which is what every check has to reason around."""
    settings: dict[str, object] = {"tools": TOOLS}
    settings.update(overrides)
    return ScriptedMcpServer(url, **settings)  # type: ignore[arg-type]


def findings(
    rule: Rule, server: ScriptedMcpServer, *, credential: str | None = None
) -> list[Finding]:
    """Run one rule against a scripted server and return everything it reported."""
    target = McpServerTarget(
        server.url, credential=credential, sender=server, discovery_sender=server
    )
    return list(rule.run(target, RuleContext()))


def summaries(reported: list[Finding]) -> list[str]:
    """The evidence lines, for asserting on what a finding actually said."""
    return [finding.evidence.summary for finding in reported]


def outcomes(reported: list[Finding]) -> list[str | None]:
    """The verdict of each report: `inconclusive` where a check declined to answer."""
    return [finding.verdict.outcome if finding.verdict else None for finding in reported]


def unreachable(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
    url: str,
    *,
    method: str = "POST",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    alongside: str | None = None,
    discovery: DiscoveryScope | None = None,
) -> RawReply:
    """A sender for the server that is not there."""
    raise McpError(f"could not reach {url}: connection refused")


class ServingAt:
    """A scripted server that answers one discovery address with `body`, whatever it serves."""

    def __init__(self, server: ScriptedMcpServer, address: str, body: bytes) -> None:
        self.server = server
        self.url = server.url
        self.address = address
        self.body = body

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        """Answer `address` with the configured body and pass every other request on."""
        if method == "GET" and url == self.address:
            return RawReply(status=200, headers={}, body=self.body)
        return self.server(url, method=method, body=body, headers=headers)


def findings_through(
    rule: Rule, sender: ServingAt, *, credential: str | None = None
) -> list[Finding]:
    """Run one rule against a server reached through `sender`."""
    target = McpServerTarget(
        sender.url, credential=credential, sender=sender, discovery_sender=sender
    )
    return list(rule.run(target, RuleContext()))
