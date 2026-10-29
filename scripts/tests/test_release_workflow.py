"""The publish waits for CI on the tagged commit, whoever pushed the tag.

`release.py` waits for green CI before it creates the tag, but a tag pushed by hand
skips that wait. The workflow therefore checks the CI run for `github.sha` itself, in a
job the publish depends on, and every way of not knowing is a refusal.

The step's script is run here with bash against a fake `gh` on PATH, so the test
exercises the shell the runner executes, not a description of it.
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_SHA = "0123456789abcdef0123456789abcdef01234567"
_FAKE_GH = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
case "$1 $2" in
  "run list") [ -n "${FAKE_LIST_FAILS:-}" ] && exit 1; printf '%s' "$FAKE_LIST" ;;
  "run watch") exit "${FAKE_WATCH_EXIT:-0}" ;;
  "run view") printf '%s\\n' "$FAKE_VIEW" ;;
  *) exit 64 ;;
esac
"""


def _jobs() -> dict[str, dict[str, object]]:
    workflow = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    jobs: dict[str, dict[str, object]] = workflow["jobs"]
    return jobs


def _gate() -> dict[str, object]:
    gate = _jobs().get("ci-passed")
    if gate is None:
        pytest.fail("release.yml has no `ci-passed` job")
    return gate


def _step() -> dict[str, object]:
    steps = _gate()["steps"]
    if not isinstance(steps, list) or len(steps) != 1:
        pytest.fail("the CI gate is expected to be one step")
    step: dict[str, object] = steps[0]
    return step


def test_the_publish_depends_on_the_ci_gate() -> None:
    needs = _jobs()["publish"].get("needs")
    assert needs == "ci-passed" or (isinstance(needs, list) and "ci-passed" in needs)
    assert _jobs()["publish"]["environment"] == "pypi"


def test_the_ci_gate_reads_runs_and_nothing_else() -> None:
    gate = _gate()
    assert gate["permissions"] == {"actions": "read"}
    assert "uses" not in _step(), "the gate runs the gh CLI on the runner, not a new action"
    env = _step()["env"]
    assert isinstance(env, dict)
    assert env["SHA"] == "${{ github.sha }}"
    assert env["GH_TOKEN"] == "${{ github.token }}"  # noqa: S105 — an expression, not a secret


def _run_gate(tmp_path: Path, **fake: str) -> tuple[subprocess.CompletedProcess[str], str]:
    gh = tmp_path / "bin" / "gh"
    gh.parent.mkdir()
    gh.write_text(_FAKE_GH, encoding="utf-8")
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "gh.log"
    script = tmp_path / "gate.sh"
    script.write_text(str(_step()["run"]), encoding="utf-8")
    environment = {
        "PATH": f"{gh.parent}{os.pathsep}{os.environ['PATH']}",
        "SHA": _SHA,
        "GH_TOKEN": "token",
        "GH_REPO": "owner/repo",
        "FAKE_GH_LOG": str(log),
        **fake,
    }
    done = subprocess.run(  # noqa: S603 — bash running the workflow's own step
        ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return done, log.read_text(encoding="utf-8") if log.exists() else ""


def test_a_green_ci_run_lets_the_publish_start(tmp_path: Path) -> None:
    done, calls = _run_gate(tmp_path, FAKE_LIST="42 completed success")

    assert done.returncode == 0, done.stdout + done.stderr
    listing = calls.splitlines()[0]
    assert f"--commit {_SHA}" in listing or f"--commit={_SHA}" in listing
    assert "ci.yml" in listing


@pytest.mark.parametrize(
    "fake",
    [
        {"FAKE_LIST": "42 completed failure"},
        {"FAKE_LIST": "42 completed cancelled"},
        {"FAKE_LIST": ""},
        {"FAKE_LIST_FAILS": "1"},
        {"FAKE_LIST": "42 in_progress ", "FAKE_WATCH_EXIT": "1", "FAKE_VIEW": "failure"},
        {"FAKE_LIST": "42 in_progress ", "FAKE_WATCH_EXIT": "0", "FAKE_VIEW": ""},
    ],
)
def test_anything_but_a_successful_ci_run_stops_the_publish(
    tmp_path: Path, fake: dict[str, str]
) -> None:
    done, _ = _run_gate(tmp_path, **fake)

    assert done.returncode != 0, done.stdout + done.stderr


def test_a_ci_run_still_going_is_waited_for(tmp_path: Path) -> None:
    done, calls = _run_gate(
        tmp_path, FAKE_LIST="42 in_progress ", FAKE_WATCH_EXIT="0", FAKE_VIEW="success"
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert any(line.startswith("run watch 42") for line in calls.splitlines())
