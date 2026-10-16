"""`probe --output` and `rule test --write-corpus` never write over a file the command reads."""

from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from test_grade_cli import _TARGET, _App, _profile, _rules
from test_rule_test_cli import _ALL_THREE, _rules_dir
from typer.testing import CliRunner

runner = CliRunner()


def _probe_writing_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> tuple[int, Path]:
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)
    rules = _rules(tmp_path)
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            _TARGET,
            "--model",
            "m",
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


def test_control_a_probe_output_naming_the_suite_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, suite = _probe_writing_over(tmp_path, monkeypatch, "answers.yaml")

    assert code == ExitCode.INVALID_USAGE
    assert suite.read_text(encoding="utf-8").startswith("{")


def test_a_probe_output_naming_the_suites_dataset_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, dataset = _probe_writing_over(tmp_path, monkeypatch, "answers.jsonl")

    first_line = dataset.read_text(encoding="utf-8").splitlines()[0]
    assert (code, '"guardana_dataset"' in first_line) == (ExitCode.INVALID_USAGE, True), code


_POLICY = "rules:\n  include: ['acme.*']\n"


def _corpus_to(tmp_path: Path, destination: Path) -> int:
    profile = tmp_path / "guardana.yaml"
    profile.write_text(_POLICY, encoding="utf-8")
    rules = _rules_dir(tmp_path, _ALL_THREE)
    result = runner.invoke(
        app,
        [
            "rule",
            "test",
            "acme.*",
            "--profile",
            str(profile),
            "--rules",
            str(rules),
            "--write-corpus",
            str(destination),
        ],
    )
    return result.exit_code


def test_control_a_corpus_beside_the_profile_leaves_the_profile_as_it_was(tmp_path: Path) -> None:
    code = _corpus_to(tmp_path, tmp_path / "mine.jsonl")

    assert code == 0
    assert (tmp_path / "guardana.yaml").read_text(encoding="utf-8") == _POLICY
    assert (tmp_path / "mine.jsonl").read_text(encoding="utf-8").startswith('{"messages"')


@pytest.mark.parametrize("named", ["guardana.yaml", "rules/r.yaml"])
def test_a_corpus_naming_a_file_the_command_reads_is_refused(tmp_path: Path, named: str) -> None:
    code = _corpus_to(tmp_path, tmp_path / named)

    kept = (tmp_path / named).read_text(encoding="utf-8")
    assert (code, kept.startswith('{"messages"')) == (ExitCode.INVALID_USAGE, False), code
