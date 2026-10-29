"""`probe --a2a` and `plan probe --a2a`: what each refuses, what a run saves, how it stops."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report import StopReason, load_report
from guardana.core.target import A2aAgentTarget
from guardana.core.testing import ScriptedA2aAgent
from typer.testing import CliRunner

runner = CliRunner()
_URL = "https://agent.invalid/"
_A = "cli-caller-a-token-0123456789"
_B = "cli-caller-b-token-9876543210"
_TASK = "8a2c4e6f-1b3d-4f5a-9c7e-0d2b4f6a8c1e"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


@pytest.fixture
def tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CALLER_A", _A)
    monkeypatch.setenv("CALLER_B", _B)


def _serve(monkeypatch: pytest.MonkeyPatch, **agent: Any) -> ScriptedA2aAgent:  # noqa: ANN401
    agent.setdefault("callers", {_A: "alice", _B: "bob"})
    agent.setdefault("tasks", {"alice": [_TASK]})
    scripted = ScriptedA2aAgent(_URL, **agent)

    def build(connection: Any) -> A2aAgentTarget:  # noqa: ANN401 — the connection the CLI built
        return A2aAgentTarget(
            connection.address,
            credential=connection.credential,
            other_credential=connection.other_credential,
            sender=scripted,
        )

    monkeypatch.setattr("guardana.cli._a2a_run.build_a2a_target", build)
    return scripted


def _probe(tmp_path: Path, *extra: str) -> tuple[int, str]:
    result = runner.invoke(
        app,
        [
            "probe",
            "--a2a",
            _URL,
            "--format",
            "json",
            "--output",
            str(tmp_path / "run.json"),
            *extra,
        ],
    )
    return result.exit_code, _plain(result.output)


@pytest.mark.parametrize(
    ("extra", "said"),
    [
        (["--a2a-other-token-env", "CALLER_B"], "pass --a2a-token-env for the first caller too"),
        (
            ["--a2a-token-env", "CALLER_A", "--a2a-other-token-env", "CALLER_A"],
            "hold the same value",
        ),
        (["--mcp", "https://mcp.invalid/"], "--a2a probes an A2A agent; --mcp"),
        (["--url", "https://model.invalid/"], "--a2a probes an A2A agent; --url"),
        (["--a2a-token-env", "UNSET_FOR_THIS_TEST"], "unset or empty"),
        (["--keep-exchanges"], "an A2A agent keeps none"),
    ],
)
def test_a_flag_combination_that_cannot_be_honoured_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tokens: None, extra: list[str], said: str
) -> None:
    monkeypatch.delenv("UNSET_FOR_THIS_TEST", raising=False)
    scripted = _serve(monkeypatch)

    code, output = _probe(tmp_path, *extra)

    assert code == ExitCode.INVALID_USAGE, output
    assert said in output
    assert scripted.requests == []


@pytest.mark.parametrize("command", [["probe"], ["plan", "probe"]], ids=["probe", "plan"])
def test_an_agent_path_that_is_not_a_json_card_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    scripted = _serve(monkeypatch)

    result = runner.invoke(app, [*command, "--a2a", f"{_URL}agents/foo"])

    output = _plain(result.output)
    assert result.exit_code == ExitCode.INVALID_USAGE, output
    assert "pass the agent card's URL (ending in .json) or the agent's origin" in output
    assert scripted.requests == []


def test_an_a2a_credential_flag_without_a2a_is_a_usage_error(tokens: None) -> None:
    result = runner.invoke(
        app,
        ["probe", "--url", "https://model.invalid/", "--model", "m", "--a2a-token-env", "CALLER_A"],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "--a2a cannot be combined with --url, --model; drop --a2a-token-env" in _plain(
        result.output
    )


def test_a_probe_saves_the_run_with_the_protocol_and_without_any_credential_or_task_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tokens: None
) -> None:
    _serve(monkeypatch, owner_bound=False)

    code, output = _probe(
        tmp_path, "--a2a-token-env", "CALLER_A", "--a2a-other-token-env", "CALLER_B"
    )

    assert code == ExitCode.POLICY_FAILED, output
    saved_text = (tmp_path / "run.json").read_text(encoding="utf-8")
    saved = load_report(tmp_path / "run.json").result
    assert saved.protocols == {"a2a": "1.0"}
    assert [f.rule_id for f in saved.findings] == ["guardana.a2a.task_visibility"]
    for secret in (_A, _B, _TASK):
        assert secret not in saved_text
        assert secret not in output
    document = json.loads(saved_text)
    assert document["run"]["coverage"]["protocols"] == {"a2a": "1.0"}


def test_an_agent_that_does_not_answer_exits_4_with_the_run_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch, silent_after=0)

    code, output = _probe(tmp_path)

    assert code == ExitCode.TARGET_UNAVAILABLE, output
    assert "did not answer" in output
    saved = load_report(tmp_path / "run.json").result
    assert saved.stopped_by is StopReason.TARGET_UNAVAILABLE


def test_a_refused_first_caller_exits_4_naming_the_a2a_token_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tokens: None
) -> None:
    _serve(monkeypatch, statuses={"ListTasks": 401})

    code, output = _probe(
        tmp_path, "--a2a-token-env", "CALLER_A", "--a2a-other-token-env", "CALLER_B"
    )

    assert code == ExitCode.TARGET_UNAVAILABLE, output
    assert "--a2a-token-env" in output
    assert "--mcp-token-env" not in output
    assert _A not in (tmp_path / "run.json").read_text(encoding="utf-8")


def test_plan_probe_prices_the_a2a_rules_without_contacting_the_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError("plan probe sent a request")

    monkeypatch.setattr("guardana.core.target._mcp_http.HttpSender.__call__", refuse)

    result = runner.invoke(app, ["plan", "probe", "--a2a", _URL, "--format", "json"])

    assert result.exit_code == 0, result.output
    plan = json.loads(result.output)
    planned = json.dumps(plan)
    for rule_id in (
        "guardana.a2a.agent_card",
        "guardana.a2a.caller_identity",
        "guardana.a2a.task_visibility",
    ):
        assert rule_id in planned


def test_plan_probe_refuses_a2a_beside_another_target() -> None:
    result = runner.invoke(app, ["plan", "probe", "--a2a", _URL, "--mcp", "https://mcp.invalid/"])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "--a2a prices an A2A agent" in _plain(result.output)
