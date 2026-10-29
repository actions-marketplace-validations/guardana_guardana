"""A run reads the calibration file its profile names, wherever the command was started.

A committed profile listing `calibrations: [cal.json]` means the file beside it; reading
it against the working directory made the same profile fail from a hook or a CI step, or
pick up whatever `cal.json` happened to sit in the directory the command ran from.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from guardana.cli._run_meta import calibrations_or_exit
from guardana.core.calibration.store import RecordedCalibration, write_calibrations
from guardana.core.profile import load_profile


def _calibration_of(evaluator: str, path: Path) -> None:
    write_calibrations(
        path,
        {
            evaluator: RecordedCalibration(
                evaluator=evaluator,
                dataset_digest="sha256:" + "ab" * 32,
                measured_at=datetime(2026, 1, 1, tzinfo=UTC),
                brier=0.1,
                ece=0.05,
                samples=60,
            )
        },
    )


def test_a_run_reads_the_calibration_beside_the_profile_not_the_one_in_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    _calibration_of("canary", config / "cal.json")
    profile = config / "guardana.yaml"
    profile.write_text("name: t\ncalibrations: ['cal.json']\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _calibration_of("keyword", elsewhere / "cal.json")
    monkeypatch.chdir(elsewhere)

    measured = calibrations_or_exit(load_profile(profile))

    assert set(measured) == {"canary"}
