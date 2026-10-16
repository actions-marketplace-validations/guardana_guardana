"""`probe --mcp` looks at every authorization server a protected resource names."""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from guardana.core.target import McpServerTarget
from guardana.core.testing import ScriptedMcpServer
from typer.testing import CliRunner

runner = CliRunner()
_URL = "https://192.0.2.10/mcp"
_ISSUER = "https://192.0.2.10"
_METADATA_SERVICE = "https://169.254.169.254"
_CALLER = "audit-operator-token-0123456789"
_RULE = "guardana.mcp.discovery_target"


def _probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, issuers: list[str]
) -> tuple[ScriptedMcpServer, dict[str, Any]]:
    server = ScriptedMcpServer(
        _URL,
        tools=[{"name": "lookup", "description": "Look a record up by its key."}],
        credential=_CALLER,
        challenge=f'Bearer resource_metadata="{_ISSUER}/.well-known/oauth-protected-resource"',
        resource_metadata={
            "resource": _ISSUER,
            "authorization_servers": issuers,
            "scopes_supported": ["records:read"],
        },
        authorization_metadata={
            "issuer": _ISSUER,
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["records:read"],
            "authorization_response_iss_parameter_supported": True,
        },
    )
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(
            server.url, credential=connection.credential, sender=server, discovery_sender=server
        ),
    )
    monkeypatch.setenv("AUDIT_MCP_TOKEN", _CALLER)
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            _URL,
            "--mcp-token-env",
            "AUDIT_MCP_TOKEN",
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    if not saved.exists():
        raise RuntimeError(f"the probe saved no run: {result.output}")
    return server, json.loads(saved.read_text(encoding="utf-8"))


def _reported(document: dict[str, Any]) -> list[str]:
    return [
        entry["evidence"]["summary"] for entry in document["findings"] if entry["rule_id"] == _RULE
    ]


def _fetched_hosts(server: ScriptedMcpServer) -> set[str]:
    return {url.split("/")[2] for method, url, _ in server.requests if method == "GET"}


def test_control_a_metadata_service_named_first_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, document = _probe(tmp_path, monkeypatch, [_METADATA_SERVICE, _ISSUER])

    assert any("169.254.169.254" in said for said in _reported(document))


def test_a_metadata_service_named_second_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, document = _probe(tmp_path, monkeypatch, [_ISSUER, _METADATA_SERVICE])

    assert any("169.254.169.254" in said for said in _reported(document)), (
        document["run"]["result_summary"],
        sorted(_fetched_hosts(server)),
    )
