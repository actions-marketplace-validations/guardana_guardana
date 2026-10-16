"""`grade --output` never writes over a dataset the suite it grades with reads."""

from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from test_grade_cli import _App, _kept, _profile, _rules
from typer.testing import CliRunner

runner = CliRunner()


def _grade_writing_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> tuple[int, Path]:
    sidecar = _kept(monkeypatch, tmp_path)
    graded = tmp_path / "graded"
    graded.mkdir()
    rules = _rules(graded)
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)
    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(rules),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(rules / name),
        ],
    )
    return result.exit_code, rules / name


def test_control_an_output_naming_the_suite_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, suite = _grade_writing_over(tmp_path, monkeypatch, "answers.yaml")

    assert code == ExitCode.INVALID_USAGE
    assert suite.read_text(encoding="utf-8").startswith("{")


def test_an_output_naming_the_suites_dataset_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, dataset = _grade_writing_over(tmp_path, monkeypatch, "answers.jsonl")

    first_line = dataset.read_text(encoding="utf-8").splitlines()[0]
    assert (code, '"guardana_dataset"' in first_line) == (ExitCode.INVALID_USAGE, True), code
