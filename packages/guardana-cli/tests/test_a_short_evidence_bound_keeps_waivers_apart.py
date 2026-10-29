"""A short evidence bound never lets a different finding match a waiver written for another."""

from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
"""GLOBAL os.system, one string argument, REDUCE."""

_EXEC = b"\x80\x02cbuiltins\nexec\nX\x02\x00\x00\x00id\x85R."
"""GLOBAL builtins.exec, one string argument, REDUCE: a different callable."""


def _rescan_after_swap(tmp_path: Path, privacy: str) -> int:
    model = tmp_path / "model"
    model.mkdir()
    weights = model / "weights.pkl"
    weights.write_bytes(_SYSTEM)
    profile = tmp_path / "guardana.yaml"
    profile.write_text(f"name: t\n{privacy}", encoding="utf-8")
    baseline = tmp_path / "baseline.yaml"
    created = runner.invoke(
        app,
        ["baseline", "create", str(model), "--profile", str(profile), "--output", str(baseline)],
    )
    assert created.exit_code == ExitCode.OK, created.output
    weights.write_bytes(_EXEC)
    result = runner.invoke(
        app, ["scan", str(model), "--profile", str(profile), "--baseline", str(baseline)]
    )
    return result.exit_code


def test_control_the_default_bound_keeps_the_swapped_callable_failing(tmp_path: Path) -> None:
    assert _rescan_after_swap(tmp_path, "") == ExitCode.POLICY_FAILED


def test_a_short_bound_keeps_the_swapped_callable_failing(tmp_path: Path) -> None:
    privacy = "privacy:\n  max_evidence_bytes: 32\n"

    assert _rescan_after_swap(tmp_path, privacy) == ExitCode.POLICY_FAILED
