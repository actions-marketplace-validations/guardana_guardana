"""The scripted MCP servers the MCP rules sample themselves against.

Built fresh for each run, so no sample sees what another one learned.
"""

from collections.abc import Callable, Mapping
from types import MappingProxyType

from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome
from guardana.core.target import McpServerTarget, RegistryEntry, Target
from guardana.core.testing import ScriptedMcpServer

SERVER = "https://mcp.invalid/mcp"
"""A name reserved never to resolve, so no sample can reach a real host."""

PROTECTED = "https://192.0.2.10/mcp"
"""The gated server the samples that walk authorization discovery run against.

Discovery judges every address it fetches by what the address resolves to, so a
name would be looked up; an address literal is judged without a lookup, and one
from this documentation range is routed nowhere.
"""

ISSUER = "https://192.0.2.10"
"""The protected server's own origin, which also serves as its authorization server."""

UNSAFE_ADDRESS = "https://169.254.169.254"
"""The cloud metadata address, which a client is refused however local its server is."""

MODERN_REVISION = "2026-07-28"
UNSPOKEN_REVISION = "2031-01-01"
"""A revision guardana does not speak, so nothing a server offering only it says is read."""

CREDENTIAL = "sample-operator-token"
TOOLS: tuple[Mapping[str, object], ...] = (
    MappingProxyType({"name": "lookup", "description": "Look a record up by its key."}),
)
REGISTRY_NAME = "io.invalid.samples/lookup"
REPORTED_RELEASE = "1.4.0"

# Read-only because every sample server is handed these same objects: a sample that
# changed one in place would change what every later sample is served.
RESOURCE_METADATA: Mapping[str, object] = MappingProxyType(
    {
        "resource": ISSUER,
        "authorization_servers": (ISSUER,),
        "scopes_supported": ("records:read", "records:write"),
    }
)
AUTHORIZATION_METADATA: Mapping[str, object] = MappingProxyType(
    {
        "issuer": ISSUER,
        "code_challenge_methods_supported": ("S256",),
        "scopes_supported": ("records:read",),
        "authorization_response_iss_parameter_supported": True,
    }
)
CHALLENGE = (
    f'Bearer resource_metadata="{ISSUER}/.well-known/oauth-protected-resource", '
    f'scope="records:read"'
)


def open_server(**behaviour: object) -> ScriptedMcpServer:
    """Build a server that answers anybody, `2025-11-25` unless `behaviour` names revisions."""
    return _server(SERVER, behaviour)


def gated_server(**behaviour: object) -> ScriptedMcpServer:
    """Build an `open_server` that refuses every caller not presenting `CREDENTIAL`."""
    return open_server(credential=CREDENTIAL, **behaviour)


def protected_server(**behaviour: object) -> ScriptedMcpServer:
    """Build a gated server at `PROTECTED` publishing a conforming authorization surface.

    `behaviour` replaces any part of that surface, so each sample varies one thing.
    """
    surface: dict[str, object] = {
        "credential": CREDENTIAL,
        "challenge": CHALLENGE,
        "resource_metadata": RESOURCE_METADATA,
        "authorization_metadata": AUTHORIZATION_METADATA,
    }
    return _server(PROTECTED, {**surface, **behaviour})


def unspoken_server() -> ScriptedMcpServer:
    """Build a server offering only `UNSPOKEN_REVISION`, so no observation can be made of it."""
    return open_server(protocol_versions=(UNSPOKEN_REVISION,))


def target(
    server: ScriptedMcpServer,
    *,
    credential: str | None = None,
    registry_entry: RegistryEntry | None = None,
) -> McpServerTarget:
    """Build a target that reaches `server` and nothing else."""
    return McpServerTarget(
        server.url,
        credential=credential,
        sender=server,
        discovery_sender=server,
        registry_entry=registry_entry,
    )


def entry(
    *, remotes: tuple[str, ...] = (SERVER,), version: str = REPORTED_RELEASE
) -> RegistryEntry:
    """Build a registry entry for the sample server, publishing `remotes` at `version`."""
    return RegistryEntry.from_document(
        {
            "name": REGISTRY_NAME,
            "version": version,
            "remotes": [{"type": "streamable-http", "url": url} for url in remotes],
        }
    )


def sample(name: str, outcome: FixtureOutcome, build: Callable[[], Target]) -> DeclaredFixture:
    """Declare one sample, built afresh each time the rule is verified."""
    return DeclaredFixture(name, outcome, build)


def _server(url: str, behaviour: Mapping[str, object]) -> ScriptedMcpServer:
    settings: dict[str, object] = {
        "tools": TOOLS,
        "server_info": {"name": "lookup", "version": REPORTED_RELEASE},
        **behaviour,
    }
    return ScriptedMcpServer(url, **{k: _thawed(v) for k, v in settings.items()})  # type: ignore[arg-type]


def _thawed(value: object) -> object:
    """Copy a read-only sample document into the plain JSON values a server serialises."""
    if isinstance(value, Mapping):
        return {key: _thawed(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thawed(item) for item in value]
    return value
