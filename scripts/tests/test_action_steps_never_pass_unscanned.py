"""The Action's scan and gate steps, run with bash as a runner runs them, never pass unscanned.

`uvx` is replaced by a stub that runs this checkout's `guardana` and leaves a marker, so a
case can tell a scan that ran from one that never started.
"""

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]

_TLS_OFF = "import requests\n\nrequests.get('https://models.example.invalid/w.bin', verify=False)\n"
"""A source file `scan` reports (exit 1)."""


@dataclass(frozen=True)
class _Job:
    scan_exit: str
    job_exit: int
    scanned: bool


def _step(name: str) -> str:
    action = yaml.safe_load((_ROOT / "action.yml").read_text(encoding="utf-8"))
    (step,) = [s for s in action["runs"]["steps"] if s.get("name") == name]
    return str(step["run"])


def _bash(script: str, cwd: Path, env: dict[str, str]) -> int:
    path = cwd.parent / f"{abs(hash(script))}.sh"
    path.write_text(script, encoding="utf-8")
    done = subprocess.run(  # noqa: S603 — bash running the Action's own step
        ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(path)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode


def _uvx_stub(bin_dir: Path, marker: Path, *, resolves: bool) -> None:
    guardana = shutil.which("guardana")
    assert guardana is not None
    body = f'#!/bin/bash\ntouch "{marker}"\n' + (
        'shift 2\nshift\nexec "' + guardana + '" "$@"\n' if resolves else "exit 1\n"
    )
    stub = bin_dir / "uvx"
    stub.write_text(body, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)


def _job(  # noqa: PLR0913 — one keyword per Action input a case varies
    tmp_path: Path,
    *,
    path: str,
    sarif: str,
    fail_on_findings: str = "false",
    resolves: bool = True,
    args: str = "",
) -> _Job:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    marker = tmp_path / "uvx-ran"
    _uvx_stub(bin_dir, marker, resolves=resolves)
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    base = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output),
        "RUNNER_TEMP": str(tmp_path),
    }
    installed = _bash(
        _step("Install Guardana"), workspace, {**base, "GUARDANA_VERSION": "1.0.0rc3"}
    )
    if installed != 0:
        return _Job(scan_exit="", job_exit=installed, scanned=marker.exists())
    _bash(
        _step("Run Guardana scan"),
        workspace,
        {
            **base,
            "GUARDANA_PATH": path,
            "GUARDANA_ARGS": args,
            "GUARDANA_SARIF": sarif,
            "GUARDANA_SPEC": _outputs(output)["spec"],
        },
    )
    recorded = _outputs(output)
    scan_exit = recorded.get("exit_code", "")
    job_exit = _bash(
        _step("Enforce the gate"),
        workspace,
        {
            **base,
            "GUARDANA_EXIT": scan_exit,
            "GUARDANA_REPORTED": recorded.get("reported", ""),
            "GUARDANA_FAIL_ON_FINDINGS": fail_on_findings,
        },
    )
    return _Job(scan_exit=scan_exit, job_exit=job_exit, scanned=marker.exists())


def _outputs(output: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in output.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )


def test_control_a_reported_file_fails_the_job_when_findings_are_enforced(tmp_path: Path) -> None:
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "app.py").write_text(_TLS_OFF, encoding="utf-8")

    job = _job(tmp_path, path="app.py", sarif="guardana.sarif", fail_on_findings="true")

    assert (job.scan_exit, job.job_exit, job.scanned) == ("1", 1, True)


def test_a_sarif_file_naming_the_scanned_file_never_passes_the_job(tmp_path: Path) -> None:
    (tmp_path / "workspace").mkdir()
    source = tmp_path / "workspace" / "app.py"
    source.write_text(_TLS_OFF, encoding="utf-8")

    job = _job(tmp_path, path="app.py", sarif="app.py", fail_on_findings="true")

    assert job.job_exit != 0, (job, source.read_text(encoding="utf-8")[:80])


def test_a_sarif_path_whose_directory_is_missing_never_passes_an_advisory_job(
    tmp_path: Path,
) -> None:
    job = _job(tmp_path, path=".", sarif="reports/guardana.sarif", fail_on_findings="false")

    assert job.job_exit != 0, job


def test_a_cli_that_could_not_be_installed_never_passes_an_advisory_job(tmp_path: Path) -> None:
    job = _job(tmp_path, path=".", sarif="guardana.sarif", resolves=False)

    assert job.job_exit != 0, job


def test_a_misspelt_fail_on_findings_does_not_waive_findings(tmp_path: Path) -> None:
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "app.py").write_text(_TLS_OFF, encoding="utf-8")

    job = _job(tmp_path, path="app.py", sarif="guardana.sarif", fail_on_findings="treu")

    assert job.job_exit != 0, job


def test_a_help_run_never_passes_the_job(tmp_path: Path) -> None:
    job = _job(tmp_path, path=".", sarif="guardana.sarif", args="--help")

    assert job.job_exit != 0, job
