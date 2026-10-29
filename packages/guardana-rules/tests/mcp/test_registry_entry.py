"""Whether the server that answered is the one its registry entry publishes."""

from collections.abc import Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.report import Finding
from guardana.core.rule import RuleContext
from guardana.core.rule.verify import verify_rule
from guardana.core.severity import Severity
from guardana.core.target import McpServerTarget, RegistryEntry
from guardana.core.target._mcp_wire import Wire
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpRegistryEntryRule
from mcp_fixtures import CREDENTIAL, ROUTABLE, TOOLS, outcomes, summaries

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpRegistryEntryRule()
_NAME = "io.example/lookup"
_VERSION = "2.0.0"


def _entry(*remotes: str, version: str = _VERSION) -> RegistryEntry:
    return RegistryEntry.from_document(
        {
            "name": _NAME,
            "version": version,
            "remotes": [{"type": "streamable-http", "url": url} for url in remotes],
        }
    )


def _run(
    entry: RegistryEntry,
    *,
    reported: Mapping[str, object] | None = None,
    presented: str | None = None,
    **behaviour: object,
) -> list[Finding]:
    server = ScriptedMcpServer(
        ROUTABLE,
        tools=TOOLS,
        server_info=reported or {"name": "lookup", "version": _VERSION},
        **behaviour,  # type: ignore[arg-type]
    )
    target = McpServerTarget(
        ROUTABLE,
        credential=presented,
        sender=server,
        discovery_sender=server,
        registry_entry=entry,
    )
    return list(RULE.run(target, RuleContext()))


def test_a_server_at_a_published_url_reporting_the_published_version_is_silent() -> None:
    assert _run(_entry(ROUTABLE)) == []


def test_a_published_url_with_a_variable_matches_the_server() -> None:
    assert _run(_entry("https://93.184.215.14/{path}/")) == []


def test_a_server_at_a_url_no_remote_publishes_is_medium() -> None:
    reported = _run(_entry("https://mcp.example.com/mcp"))

    assert [f.severity for f in reported] == [Severity.MEDIUM]
    assert summaries(reported) == [
        f"the server at {ROUTABLE} is not a remote its registry entry {_NAME} publishes"
    ]


def test_an_entry_without_remotes_publishes_no_url() -> None:
    reported = _run(_entry())

    assert [f.severity for f in reported] == [Severity.MEDIUM]


def test_a_different_reported_version_is_low_and_worded_as_a_self_report() -> None:
    reported = _run(_entry(ROUTABLE), reported={"name": "lookup", "version": "1.9.0"})

    assert [f.severity for f in reported] == [Severity.LOW]
    assert "reports version 1.9.0" in summaries(reported)[0]
    assert "publishes 2.0.0" in summaries(reported)[0]
    assert "own claim" in summaries(reported)[0]


def test_a_server_reporting_no_version_is_inconclusive() -> None:
    for info in ({"name": "lookup", "version": ""}, {"name": "lookup"}):
        reported = _run(_entry(ROUTABLE), reported=info)

        assert outcomes(reported) == ["inconclusive"]
        assert summaries(reported) == [f"the server reports no version to compare with {_VERSION}"]


def test_the_version_reported_in_discovery_is_compared_on_a_modern_server() -> None:
    reported = _run(
        _entry(ROUTABLE),
        reported={"name": "lookup", "version": "9"},
        protocol_versions=["2026-07-28"],
    )

    assert [f.severity for f in reported] == [Severity.LOW]


def test_a_server_refusing_the_opening_leaves_the_version_open() -> None:
    reported = _run(_entry(ROUTABLE), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be read" in summaries(reported)[0]


class _Stdio:
    """A transport standing in for a started process: the HTTP half is absent."""

    def speak(self, wire: Wire) -> None:
        """Accept the revision."""

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        """Answer the handshake with an identity, and nothing else."""
        if method == "initialize":
            return {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": {"name": "lookup", "version": "1.0.0"},
            }
        return {}

    def notify(self, method: str) -> None:
        """Accept the notification."""

    def close(self) -> None:
        """Nothing to release."""


def test_over_stdio_only_the_version_is_compared() -> None:
    target = McpServerTarget(transport=_Stdio(), registry_entry=_entry("https://elsewhere/mcp"))

    reported = list(RULE.run(target, RuleContext()))

    assert [f.severity for f in reported] == [Severity.LOW]
    assert "reports version 1.0.0" in summaries(reported)[0]


def test_the_rule_classifies_its_own_samples() -> None:
    assert verify_rule(RULE, RuleContext()).is_proven


def test_a_gated_server_answers_the_opening_with_the_operator_credential() -> None:
    assert _run(_entry(ROUTABLE), presented=CREDENTIAL, credential=CREDENTIAL) == []
