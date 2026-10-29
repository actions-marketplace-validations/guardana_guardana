"""An unusable `evaluators:` block is a usage error in one line, before anything is sent."""

from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_ENDPOINT = ["--url", "http://127.0.0.1:9/v1", "--model", "m"]


_COMMANDS = pytest.mark.parametrize(
    "command",
    [
        ["plan", "probe", *_ENDPOINT],
        ["probe", *_ENDPOINT],
        ["monitor", *_ENDPOINT],
        ["calibrate"],
        ["rule", "test"],
    ],
    ids=["plan", "probe", "monitor", "calibrate", "rule-test"],
)


@_COMMANDS
def test_a_judge_without_a_model_exits_invalid_usage_without_a_traceback(
    tmp_path: Path, command: list[str]
) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "evaluators:\n  llm_judge:\n    endpoint: 'http://127.0.0.1:9/v1'\n", encoding="utf-8"
    )

    result = runner.invoke(app, [*command, "--profile", str(profile)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    errors = [line for line in result.stderr.splitlines() if not line.startswith("warning: ")]
    assert errors == ["error: evaluators.llm_judge.model must be a non-empty string"]


@_COMMANDS
@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://judge-user:hunter2@judge.internal/v1",
        "judge.internal/v1?key=hunter2",
        "hunter2:x@judge.internal",
    ],
    ids=["ftp-with-userinfo", "no-scheme", "secret-read-as-scheme"],
)
def test_a_judge_endpoint_that_cannot_be_built_exits_invalid_usage_without_its_secret(
    tmp_path: Path, command: list[str], endpoint: str
) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        f"evaluators:\n  llm_judge:\n    endpoint: '{endpoint}'\n    model: j\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, [*command, "--profile", str(profile)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert isinstance(result.exception, SystemExit), result.exception
    assert "hunter2" not in result.stdout
    assert "hunter2" not in result.stderr
    errors = [line for line in result.stderr.splitlines() if not line.startswith("warning: ")]
    assert len(errors) == 1, result.stderr
    assert errors[0].startswith("error: evaluators.llm_judge.endpoint "), result.stderr
