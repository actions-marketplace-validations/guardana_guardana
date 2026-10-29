"""A run whose judge calibration was measured under another prompt version says so on stderr.

The calibration stops tempering confidence and correcting rates once the judge's id moves,
and nothing in the run's result would otherwise tell the operator why.
"""

import re
from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.main import app
from guardana.core.target.endpoint import ChatMessage
from typer.testing import CliRunner, Result

runner = CliRunner()


class _RefusesToBeCalled:
    """A plan that sends anything fails the test."""

    def send(
        self, base_url: str, model: str, messages: list[ChatMessage], api_key: str | None
    ) -> str:
        raise AssertionError("guardana plan must not send a request")


def _plain(text: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", text).split())


def _plan_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, judge: str) -> Result:
    monkeypatch.setattr(endpoint_module, "transport_factory", _RefusesToBeCalled)
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "name: t\n"
        "evaluators:\n"
        "  llm_judge:\n"
        "    endpoint: https://judge.example/v1\n"
        "    model: j\n"
        f"{judge}"
        "    calibration: {evaluator_id: llm_judge@2025.1, accuracy: 0.9, samples: 40}\n",
        encoding="utf-8",
    )
    return runner.invoke(app, ["plan", "scan", str(scanned), "--profile", str(profile)])


def test_a_calibration_for_the_previous_default_is_warned_about_with_its_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stderr = _plain(_plan_scan(monkeypatch, tmp_path, judge="").stderr)

    assert "warning: evaluators.llm_judge.calibration was measured for llm_judge@2025.1" in stderr
    assert 'prompt_version: "2025.1"' in stderr


def test_a_calibration_for_the_pinned_version_is_not_warned_about(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _plan_scan(monkeypatch, tmp_path, judge="    prompt_version: '2025.1'\n")

    assert result.exit_code == 0, result.output
    assert "warning" not in _plain(result.stderr), result.output
