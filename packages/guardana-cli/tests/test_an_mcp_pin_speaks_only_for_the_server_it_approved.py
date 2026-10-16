"""A pin speaks only for the server it approved, and writing one never replaces an input."""

import json
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import McpServerTarget
from guardana.core.testing import ScriptedMcpServer
from typer.testing import CliRunner, Result

runner = CliRunner()
_RULE = "guardana.agent.mcp_server_manifest"
_URL = "https://mcp.invalid/mcp"
_PROFILE = "schema_version: 1\nname: audit\n"

_STDIO_SERVER = """
import json, sys
for line in sys.stdin:
    asked = json.loads(line)
    if "id" not in asked:
        continue
    method = asked.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [{"name": "lookup", "description": "Look a record up by its key."}]}
    else:
        reply = {"jsonrpc": "2.0", "id": asked["id"],
                 "error": {"code": -32601, "message": "Method not found"}}
        sys.stdout.write(json.dumps(reply) + "\\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": asked["id"], "result": result}) + "\\n")
    sys.stdout.flush()
"""


def _command(tmp_path: Path, name: str) -> str:
    script = tmp_path / name
    script.write_text(_STDIO_SERVER, encoding="utf-8")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}"


def _approve_stdio(tmp_path: Path, command: str) -> Path:
    pin = tmp_path / "approved.json"
    written = runner.invoke(
        app, ["probe", "--mcp", command, "--allow-exec", "--write-mcp-pin", str(pin)]
    )
    if written.exit_code != ExitCode.OK or not pin.exists():
        raise RuntimeError(f"the pin was not written: {written.output}")
    return pin


def _probe_stdio(tmp_path: Path, command: str, pin: Path) -> tuple[Result, dict[str, Any]]:
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            command,
            "--allow-exec",
            "--mcp-pin",
            str(pin),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    if not saved.exists():
        raise RuntimeError(f"the probe saved no run: {result.output}")
    return result, json.loads(saved.read_text(encoding="utf-8"))


def _declined(document: dict[str, Any]) -> list[str]:
    return [
        entry["evidence"]["summary"]
        for entry in document["unverified"]
        if entry["rule_id"] == _RULE
    ]


def test_control_a_pin_naming_another_stdio_server_is_not_compared(tmp_path: Path) -> None:
    command = _command(tmp_path, "server_a.py")
    pin = _approve_stdio(tmp_path, command)
    approved = json.loads(pin.read_text(encoding="utf-8"))
    pin.write_text(json.dumps({**approved, "server": "mcp+stdio://elsewhere"}), encoding="utf-8")

    _, document = _probe_stdio(tmp_path, command, pin)

    assert any("approved for" in said for said in _declined(document))


def test_a_pin_approved_for_one_stdio_script_does_not_speak_for_another(tmp_path: Path) -> None:
    pin = _approve_stdio(tmp_path, _command(tmp_path, "server_a.py"))

    result, document = _probe_stdio(tmp_path, _command(tmp_path, "server_b.py"), pin)

    assert any("approved for" in said for said in _declined(document)), (
        result.exit_code,
        json.loads(pin.read_text(encoding="utf-8"))["server"],
    )


def _serve(monkeypatch: pytest.MonkeyPatch) -> None:
    server = ScriptedMcpServer(_URL, tools=[{"name": "read", "description": "Read."}])
    monkeypatch.setattr(
        "guardana.cli._mcp_run.build_mcp_target",
        lambda connection: McpServerTarget(server.url, sender=server, discovery_sender=server),
    )


def test_control_an_output_naming_the_profile_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch)
    profile = tmp_path / "profile.yaml"
    profile.write_text(_PROFILE, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            _URL,
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(profile),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert profile.read_text(encoding="utf-8") == _PROFILE


def test_a_pin_written_over_the_profile_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch)
    profile = tmp_path / "profile.yaml"
    profile.write_text(_PROFILE, encoding="utf-8")

    result = runner.invoke(
        app, ["probe", "--mcp", _URL, "--profile", str(profile), "--write-mcp-pin", str(profile)]
    )

    assert profile.read_text(encoding="utf-8") == _PROFILE, result.exit_code
    assert result.exit_code == ExitCode.INVALID_USAGE
