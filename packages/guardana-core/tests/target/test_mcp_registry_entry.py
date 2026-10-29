"""A registry `server.json` read by the operator's hand, and the URLs it publishes."""

import json
from pathlib import Path

import pytest
from _offline import refuse_name_lookups
from guardana.core.target import (
    Capability,
    McpServerTarget,
    RegistryEntry,
    RegistryEntryError,
    ReportedServer,
)
from guardana.core.target._mcp_registry import MAX_ENTRY_BYTES
from guardana.core.target.protocols import CAPABILITY_SURFACE, RegistryEntryInspector
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_NAME = "io.example/lookup"


def _entry(*urls: str, version: str = "1.0.0") -> RegistryEntry:
    return RegistryEntry.from_document(
        {
            "name": _NAME,
            "version": version,
            "remotes": [{"type": "streamable-http", "url": url} for url in urls],
        }
    )


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "server.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_server_json_is_read_keeping_name_version_and_remote_urls(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "$schema": "https://static.modelcontextprotocol.io/schemas/server.schema.json",
            "name": _NAME,
            "version": "2.1.0",
            "description": "ignored",
            "remotes": [{"type": "streamable-http", "url": "https://mcp.example.com/mcp"}],
            "packages": [{"registryType": "npm"}],
        },
    )

    entry = RegistryEntry.load(path)

    assert entry == RegistryEntry(_NAME, "2.1.0", ("https://mcp.example.com/mcp",))


def test_an_entry_without_remotes_publishes_none(tmp_path: Path) -> None:
    entry = RegistryEntry.load(_write(tmp_path, {"name": _NAME, "version": "1"}))

    assert entry.remotes == ()
    assert not entry.publishes("https://mcp.example.com/mcp")


@pytest.mark.parametrize(
    ("document", "said"),
    [
        ([], "not a JSON object"),
        ({"version": "1"}, "'name'"),
        ({"name": "no-slash", "version": "1"}, "'name'"),
        ({"name": "a/b c", "version": "1"}, "'name'"),
        ({"name": _NAME, "version": ""}, "'version'"),
        ({"name": _NAME, "version": 1}, "'version'"),
        ({"name": _NAME, "version": "1", "remotes": {}}, "not a list"),
        ({"name": _NAME, "version": "1", "remotes": [{"url": "https://a"}]}, "'type'"),
        (
            {"name": _NAME, "version": "1", "remotes": [{"type": "sse", "url": "ftp://a/x"}]},
            "http or https",
        ),
        ({"name": _NAME, "version": "1", "remotes": [{"type": "sse"}]}, "http or https"),
    ],
)
def test_a_malformed_entry_is_refused_naming_what_is_wrong(
    tmp_path: Path, document: object, said: str
) -> None:
    with pytest.raises(RegistryEntryError, match=said):
        RegistryEntry.load(_write(tmp_path, document))


def test_an_entry_that_is_not_json_or_too_large_or_missing_is_refused(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    large = tmp_path / "large.json"
    large.write_bytes(b" " * (MAX_ENTRY_BYTES + 1))

    with pytest.raises(RegistryEntryError, match="not JSON"):
        RegistryEntry.load(broken)
    with pytest.raises(RegistryEntryError, match="exceeds"):
        RegistryEntry.load(large)
    with pytest.raises(RegistryEntryError, match="cannot be read"):
        RegistryEntry.load(tmp_path / "absent.json")
    assert issubclass(RegistryEntryError, ValueError)


@pytest.mark.parametrize(
    ("published", "reached"),
    [
        ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp"),
        ("https://MCP.Example.com/mcp", "HTTPS://mcp.example.COM/mcp"),
        ("https://mcp.example.com:443/mcp", "https://mcp.example.com/mcp"),
        ("http://mcp.example.com/mcp", "http://mcp.example.com:80/mcp"),
        ("https://mcp.example.com/mcp/", "https://mcp.example.com/mcp"),
        ("https://mcp.example.com/", "https://mcp.example.com"),
        ("https://mcp.example.com/mcp?v=2", "https://mcp.example.com/mcp?v=2"),
        ("https://mcp.example.com/mcp#docs", "https://mcp.example.com/mcp"),
        ("https://{tenant}.example.com/mcp", "https://acme.example.com/mcp"),
        ("https://mcp.example.com/{tenant}/mcp", "https://mcp.example.com/acme/mcp"),
        ("https://mcp.example.com/{tenant}?v=2", "https://mcp.example.com/acme?v=2"),
        ("https://[2001:db8::1]:443/mcp", "https://[2001:db8::1]/mcp"),
        ("https://mcp.example.com/mcp?t={tenant}", "https://mcp.example.com/mcp?t=acme"),
    ],
)
def test_a_reached_url_matches_the_remote_that_publishes_it(published: str, reached: str) -> None:
    assert _entry(published).publishes(reached)


@pytest.mark.parametrize(
    ("published", "reached"),
    [
        ("https://mcp.example.com/mcp", "https://mcp.example.com/other"),
        ("https://mcp.example.com/mcp", "http://mcp.example.com/mcp"),
        ("https://mcp.example.com/mcp", "https://mcp.example.com:8443/mcp"),
        ("https://mcp.example.com/mcp", "https://mcp.example.com/MCP"),
        ("https://mcp.example.com/mcp//", "https://mcp.example.com/mcp"),
        ("https://mcp.example.com/mcp?v=2", "https://mcp.example.com/mcp?v=3"),
        ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp?v=2"),
        ("https://mcp.example.com/{tenant}/mcp", "https://mcp.example.com/a/b/mcp"),
        ("https://mcp.example.com/{tenant}/mcp", "https://mcp.example.com//mcp"),
        ("https://{tenant}.example.com/mcp", "https://example.com/mcp"),
        ("https://mcp.example.com/{tenant}", "https://mcp.example.com/acme?v=2"),
        ("https://mcp.example.com/{tenant}/mcp", "https://mcp.example.com/acme?x=/mcp"),
        ("https://mcp.example.com/{tenant}?v=2", "https://mcp.example.com/acme?v=3"),
        ("https://mcp.example.com/mcp?t={tenant}", "https://mcp.example.com/mcp?t=a&x=1"),
        ("https://mcp.example.com/mcp?t={tenant}", "https://mcp.example.com/mcp?t="),
    ],
)
def test_a_reached_url_that_differs_matches_no_remote(published: str, reached: str) -> None:
    assert not _entry(published).publishes(reached)


def test_a_reported_version_of_empty_text_counts_as_none() -> None:
    assert ReportedServer.from_info({"name": "x", "version": ""}) is None
    assert ReportedServer.from_info({"name": "x"}) is None
    assert ReportedServer.from_info(None) is None
    assert ReportedServer.from_info({"version": "1"}) == ReportedServer("", "1")


def test_the_registry_capability_is_declared_only_with_an_entry() -> None:
    url = "https://93.184.215.14/mcp"
    server = ScriptedMcpServer(url)
    without = McpServerTarget(url, sender=server, discovery_sender=server)
    with_entry = McpServerTarget(
        url, sender=server, discovery_sender=server, registry_entry=_entry(url)
    )

    assert Capability.REGISTRY_ENTRY not in without.capabilities()
    assert Capability.REGISTRY_ENTRY in with_entry.capabilities()
    assert CAPABILITY_SURFACE[Capability.REGISTRY_ENTRY] is RegistryEntryInspector
    assert isinstance(with_entry, RegistryEntryInspector)
    assert with_entry.server_url() == url


def test_the_reported_server_comes_from_the_handshake_or_from_discovery() -> None:
    url = "https://93.184.215.14/mcp"
    info = {"name": "lookup", "version": "3.2.1"}
    legacy = ScriptedMcpServer(url, server_info=info)
    modern = ScriptedMcpServer(url, server_info=info, protocol_versions=["2026-07-28"])

    for server in (legacy, modern):
        target = McpServerTarget(url, sender=server, discovery_sender=server)
        assert target.reported_server() == ReportedServer("lookup", "3.2.1")
    assert [b["method"] for b in legacy.bodies] == ["server/discover", "initialize"]
    assert [b["method"] for b in modern.bodies] == ["server/discover"]
