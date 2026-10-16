"""`probe --mcp --write-mcp-pin` sends no more requests than `--max-requests` allows."""

from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import McpServerTarget
from guardana.core.testing import ScriptedMcpServer
from typer.testing import CliRunner

runner = CliRunner()
_URL = "https://93.184.215.14/mcp"


def _serve(monkeypatch: pytest.MonkeyPatch) -> ScriptedMcpServer:
    server = ScriptedMcpServer(_URL, tools=[{"name": "read", "description": "Read."}])
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )
    return server


def test_control_an_unbounded_pin_write_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _serve(monkeypatch)

    result = runner.invoke(app, ["probe", "--mcp", _URL, "--write-mcp-pin", str(tmp_path / "p")])

    assert result.exit_code == ExitCode.OK, result.output
    assert len(server.requests) > 1


def test_a_pin_write_stays_inside_max_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _serve(monkeypatch)
    pin = tmp_path / "pin.json"

    result = runner.invoke(
        app, ["probe", "--mcp", _URL, "--write-mcp-pin", str(pin), "--max-requests", "1"]
    )

    assert len(server.requests) <= 1, (result.exit_code, server.requests)
