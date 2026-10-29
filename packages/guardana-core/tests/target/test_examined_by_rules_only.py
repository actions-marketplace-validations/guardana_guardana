"""Which targets a run examines with its rules alone, decided in one place for `verify` and `plan`.

A target nothing can chat with or plant a prompt in has no probe pass to split into, so
every built-in protocol server is examined by rules only, and every chat target and every
target taking a planted prompt is not.
"""

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from _fixtures_file import fixtures_document
from guardana.core.fixtures import parse_fixtures
from guardana.core.recording import Recording
from guardana.core.target import (
    A2aAgentTarget,
    ArtifactTarget,
    Capability,
    EndpointTarget,
    McpServerTarget,
    RecordedTarget,
    Target,
    TargetKind,
    examined_by_rules_only,
)
from guardana.core.testing import (
    ScriptedA2aAgent,
    ScriptedMcpServer,
    ScriptedTransport,
    SeededApplication,
    seeded_target,
)

_MCP = "https://93.184.215.14/mcp"
_A2A = "https://agent.invalid/"


def _mcp() -> Target:
    server = ScriptedMcpServer(_MCP)
    return McpServerTarget(_MCP, sender=server, discovery_sender=server)


def _a2a() -> Target:
    return A2aAgentTarget(_A2A, sender=ScriptedA2aAgent(_A2A))


def _endpoint() -> Target:
    return EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))


def _seeded() -> Target:
    written = yaml.safe_dump(fixtures_document()).encode("utf-8")
    fixtures = parse_fixtures(written, Path("guardana-fixtures.yaml"))
    return seeded_target(fixtures, SeededApplication(fixtures))


def _recorded() -> Target:
    recording = Recording(
        name="replies",
        version="1",
        verbatim=True,
        subject=None,
        origin=None,
        exchanges=(),
        digest=None,
    )
    return RecordedTarget(recording)


@pytest.mark.parametrize("build", [_mcp, _a2a], ids=["mcp", "a2a"])
def test_a_protocol_server_is_examined_by_rules_only(build: Callable[[], Target]) -> None:
    assert examined_by_rules_only(build())


@pytest.mark.parametrize(
    "build", [_endpoint, _seeded, _recorded], ids=["endpoint", "seeded", "recorded"]
)
def test_a_target_a_rule_can_chat_with_is_probed_in_passes(build: Callable[[], Target]) -> None:
    assert not examined_by_rules_only(build())


def test_an_artifact_set_is_examined_by_rules_only(tmp_path: Path) -> None:
    assert examined_by_rules_only(ArtifactTarget(tmp_path))


class _PlantsWithoutChat(Target):
    """A pack target that takes a planted system prompt and declares no chat."""

    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.PLANT_SYSTEM_PROMPT}

    @property
    def ref(self) -> str:
        return "pack://plants-without-chat"


def test_a_target_taking_a_planted_prompt_without_chat_is_probed_in_passes() -> None:
    assert not examined_by_rules_only(_PlantsWithoutChat())
