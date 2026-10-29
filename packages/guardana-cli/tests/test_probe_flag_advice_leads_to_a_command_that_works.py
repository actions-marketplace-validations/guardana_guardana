"""A probe refusing flags that configure another target says what to drop, all at once.

Advice to add `--mcp` beside `--target`, `--a2a` or a chat endpoint led to a second
refusal; following what a refusal says now leads to a command no target check refuses.
"""

import re

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.testing import RefusingTransport
from typer.testing import CliRunner

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CHAT = ["--url", "http://192.0.2.1", "--model", "m"]


def _plain(output: str) -> str:
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> RefusingTransport:
    """The chat endpoint a probe here sends to, counting what reached it."""
    transport = RefusingTransport()
    monkeypatch.setattr("guardana.cli._endpoint.transport_factory", lambda: transport)
    return transport


@pytest.mark.parametrize(
    ("given", "said"),
    [
        (
            ["--target", "acme://agent", "--mcp-pin", "pin.json"],
            "--target cannot be combined with --mcp-pin; pass target-specific configuration "
            "through --target-option",
        ),
        (
            [
                "--target",
                "acme://agent",
                "--mcp-pin",
                "pin.json",
                "--mcp-registry-entry",
                "server.json",
                "--a2a-token-env",
                "CALLER_A",
            ],
            "--target cannot be combined with --mcp-pin, --mcp-registry-entry, --a2a-token-env;",
        ),
        (
            ["--a2a", "https://agent.invalid/", "--mcp-pin", "pin.json", "--allow-exec"],
            "--a2a probes an A2A agent; --mcp-pin, --allow-exec configure another target and "
            "would be ignored",
        ),
        (
            ["--mcp", "https://mcp.invalid/", "--a2a-token-env", "CALLER_A"],
            "--a2a-token-env names a credential for --a2a; --a2a cannot be combined with "
            "--mcp; drop --a2a-token-env",
        ),
        (
            ["--mcp-pin", "pin.json", "--a2a-token-env", "CALLER_A"],
            "--mcp cannot be combined with --a2a; pass --mcp and drop --a2a-token-env, or "
            "pass --a2a URL and drop --mcp-pin",
        ),
    ],
    ids=["target", "target-every-flag", "a2a", "mcp-beside-a2a-credential", "both-lone"],
)
def test_flags_of_another_target_are_refused_without_advising_a_second_refusal(
    model: RefusingTransport, given: list[str], said: str
) -> None:
    result = runner.invoke(app, ["probe", *given])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert said in _plain(result.output)
    assert "pass --mcp too" not in _plain(result.output)
    assert model.seen == []


@pytest.mark.parametrize(
    ("lone", "said"),
    [
        (
            ["--mcp-pin", "pin.json", "--mcp-registry-entry", "server.json"],
            "--mcp-pin, --mcp-registry-entry apply only to the MCP server --mcp names; --mcp "
            "cannot be combined with --url, --model; drop --mcp-pin, --mcp-registry-entry",
        ),
        (
            ["--a2a-token-env", "CALLER_A"],
            "--a2a-token-env names a credential for --a2a; --a2a cannot be combined with "
            "--url, --model; drop --a2a-token-env",
        ),
    ],
    ids=["mcp", "a2a"],
)
def test_a_chat_probe_given_another_targets_flags_runs_once_they_are_dropped(
    model: RefusingTransport, lone: list[str], said: str
) -> None:
    refused = runner.invoke(app, ["probe", *_CHAT, *lone])
    assert refused.exit_code == ExitCode.INVALID_USAGE, refused.output
    assert said in _plain(refused.output)
    assert model.seen == []

    advised = runner.invoke(app, ["probe", *_CHAT])

    assert advised.exit_code == ExitCode.OK, advised.output
    assert model.seen != []


def test_an_mcp_flag_alone_still_asks_for_mcp(model: RefusingTransport) -> None:
    result = runner.invoke(app, ["probe", "--mcp-pin", "pin.json"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "--mcp-pin applies only to the MCP server --mcp names; pass --mcp too" in _plain(
        result.output
    )
