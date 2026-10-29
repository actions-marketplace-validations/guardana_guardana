"""Two calibration files measuring one evaluator are refused, never settled by list order.

Exactly one measurement may correct a run and enter its evidence, so a second file for
the same evaluator is an error naming both files, and no list order picks between them.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import typer
from guardana.cli._run_meta import calibrations_or_exit
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.calibration.store import RecordedCalibration, write_calibrations
from guardana.core.profile import load_profile
from typer.testing import CliRunner

runner = CliRunner()


def _calibrations(path: Path, *evaluators: str, brier: float = 0.1) -> None:
    write_calibrations(
        path,
        {
            evaluator: RecordedCalibration(
                evaluator=evaluator,
                dataset_digest="sha256:" + "ab" * 32,
                measured_at=datetime(2026, 1, 1, tzinfo=UTC),
                brier=brier,
                ece=0.05,
                samples=60,
            )
            for evaluator in evaluators
        },
    )


def _profile(tmp_path: Path, *files: str) -> Path:
    path = tmp_path / "guardana.yaml"
    listed = ", ".join(f"'{name}'" for name in files)
    path.write_text(f"name: t\ncalibrations: [{listed}]\n", encoding="utf-8")
    return path


def test_two_files_calibrating_one_evaluator_are_refused_naming_both(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _calibrations(tmp_path / "first.json", "llm_judge", "canary", brier=0.1)
    _calibrations(tmp_path / "second.json", "llm_judge", brier=0.3)

    with pytest.raises(typer.Exit) as stopped:
        calibrations_or_exit(load_profile(_profile(tmp_path, "first.json", "second.json")))

    assert stopped.value.exit_code == ExitCode.INVALID_USAGE
    said = capsys.readouterr().err
    assert "llm_judge" in said
    assert "first.json" in said
    assert "second.json" in said


def test_a_probe_with_two_files_for_one_evaluator_exits_before_sending(tmp_path: Path) -> None:
    _calibrations(tmp_path / "first.json", "keyword")
    _calibrations(tmp_path / "second.json", "keyword")

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://127.0.0.1:9/v1",
            "--model",
            "m",
            "--profile",
            str(_profile(tmp_path, "first.json", "second.json")),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "keyword is calibrated in both" in result.stderr


def test_one_file_listed_twice_is_one_measurement(tmp_path: Path) -> None:
    _calibrations(tmp_path / "cal.json", "llm_judge", "canary")
    (tmp_path / "sub").mkdir()

    measured = calibrations_or_exit(
        load_profile(_profile(tmp_path, "cal.json", "./sub/../cal.json"))
    )

    assert set(measured) == {"llm_judge", "canary"}


def test_files_calibrating_different_evaluators_are_both_read(tmp_path: Path) -> None:
    _calibrations(tmp_path / "judge.json", "llm_judge")
    _calibrations(tmp_path / "canary.json", "canary")

    measured = calibrations_or_exit(load_profile(_profile(tmp_path, "judge.json", "canary.json")))

    assert set(measured) == {"llm_judge", "canary"}
