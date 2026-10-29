"""The Action never passes a job whose `args` turned the scan into something that is not one.

The scan and gate steps run with bash as a runner runs them, with `uvx` replaced by a stub
that runs this checkout's `guardana`; the SARIF upload is off, as `upload-sarif: false` sets it.
"""

import os
from pathlib import Path

import pytest

from tests.test_action_steps_never_pass_unscanned import _TLS_OFF, _bash, _step, _uvx_stub


def _job(tmp_path: Path, path: str, args: str) -> tuple[str, int, int]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(_TLS_OFF, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "uvx-ran"
    _uvx_stub(bin_dir, marker, resolves=True)
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    base = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "GITHUB_OUTPUT": str(output)}
    _bash(
        _step("Run Guardana scan"),
        workspace,
        {
            **base,
            "GUARDANA_PATH": path,
            "GUARDANA_ARGS": args,
            "GUARDANA_SARIF": "guardana.sarif",
            "GUARDANA_VERSION": "1.0.0rc3",
        },
    )
    if not marker.exists():
        raise RuntimeError("precondition: the scan step should have started the CLI")
    recorded = dict(
        line.split("=", 1)
        for line in output.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    scan_exit = recorded.get("exit_code", "")
    job_exit = _bash(
        _step("Enforce the gate"),
        workspace,
        {**base, "GUARDANA_EXIT": scan_exit, "GUARDANA_FAIL_ON_FINDINGS": "true"},
    )
    sarif = workspace / "guardana.sarif"
    return scan_exit, job_exit, sarif.stat().st_size if sarif.exists() else -1


@pytest.mark.parametrize(
    ("path", "scan_exit"), [("no-such-directory", "3"), ("app.py", "1")], ids=["missing", "finding"]
)
def test_control_without_args_the_scan_exit_fails_the_job(
    tmp_path: Path, path: str, scan_exit: str
) -> None:
    assert _job(tmp_path, path, "")[:2] == (scan_exit, 1)


@pytest.mark.parametrize(
    ("path", "args"),
    [("no-such-directory", "--help"), ("app.py", "--write-baseline guardana-baseline.yaml")],
    ids=["help-over-a-missing-path", "baseline-over-a-finding"],
)
def test_a_mode_that_gives_no_verdict_never_passes_the_job(
    tmp_path: Path, path: str, args: str
) -> None:
    scan_exit, job_exit, size = _job(tmp_path, path, args)

    assert job_exit != 0, (scan_exit, job_exit, size)
