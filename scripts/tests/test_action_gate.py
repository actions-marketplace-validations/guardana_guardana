"""The Action's last step: `fail-on-findings` waives findings, never a scan that did not finish.

Exit 1 is the one code that means "the scan ran and the policy failed". Every other
non-zero code means the question was not answered, and an advisory run is still not
allowed to read that as green. The step's script is run here with bash, as the runner
runs it, for every code in the exit-code contract.
"""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]


def _enforce() -> dict[str, object]:
    action = yaml.safe_load((_ROOT / "action.yml").read_text(encoding="utf-8"))
    steps: list[dict[str, object]] = action["runs"]["steps"]
    (step,) = [s for s in steps if s.get("name") == "Enforce the gate"]
    return step


def _exit(tmp_path: Path, scan_exit: str, fail_on_findings: str, reported: str = "true") -> int:
    script = tmp_path / "enforce.sh"
    script.write_text(str(_enforce()["run"]), encoding="utf-8")
    environment = {
        "PATH": os.environ["PATH"],
        "GUARDANA_EXIT": scan_exit,
        "GUARDANA_REPORTED": reported,
        "GUARDANA_FAIL_ON_FINDINGS": fail_on_findings,
    }
    done = subprocess.run(  # noqa: S603 — bash running the Action's own step
        ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode


def test_the_step_runs_whatever_fail_on_findings_says() -> None:
    step = _enforce()
    assert "fail-on-findings" not in str(step.get("if", ""))
    env = step["env"]
    assert isinstance(env, dict)
    assert env["GUARDANA_FAIL_ON_FINDINGS"] == "${{ inputs.fail-on-findings }}"
    assert env["GUARDANA_EXIT"] == "${{ steps.scan.outputs.exit_code }}"


@pytest.mark.parametrize("fail_on_findings", ["true", "false"])
def test_a_passing_scan_passes(tmp_path: Path, fail_on_findings: str) -> None:
    assert _exit(tmp_path, "0", fail_on_findings) == 0


def test_findings_fail_the_step_by_default(tmp_path: Path) -> None:
    assert _exit(tmp_path, "1", "true") == 1


def test_findings_are_advisory_when_asked(tmp_path: Path) -> None:
    assert _exit(tmp_path, "1", "false") == 0


@pytest.mark.parametrize("fail_on_findings", ["true", "false"])
@pytest.mark.parametrize("scan_exit", ["2", "3", "4", "5", "6", "7", "", "garbage"])
def test_a_scan_that_did_not_finish_fails_the_step_regardless(
    tmp_path: Path, scan_exit: str, fail_on_findings: str
) -> None:
    assert _exit(tmp_path, scan_exit, fail_on_findings) != 0


@pytest.mark.parametrize("fail_on_findings", ["treu", "True", "yes", "1", ""])
def test_a_fail_on_findings_that_is_neither_true_nor_false_fails_the_step(
    tmp_path: Path, fail_on_findings: str
) -> None:
    assert _exit(tmp_path, "1", fail_on_findings) != 0
    assert _exit(tmp_path, "0", fail_on_findings) != 0


@pytest.mark.parametrize("scan_exit", ["0", "1"])
@pytest.mark.parametrize("fail_on_findings", ["true", "false"])
def test_a_verdict_without_the_report_this_scan_wrote_fails_the_step(
    tmp_path: Path, scan_exit: str, fail_on_findings: str
) -> None:
    """`--help` exits 0 and a failed install exits 1, and neither wrote a report."""
    assert _exit(tmp_path, scan_exit, fail_on_findings, reported="false") != 0
