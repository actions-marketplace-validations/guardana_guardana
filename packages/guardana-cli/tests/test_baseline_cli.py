"""Accepted risk, with an owner and an end date — checked where a team meets it."""

import errno
from pathlib import Path

import pytest
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_INSECURE = "import requests\nrequests.get('http://x', verify=False)\n"


def _project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(_INSECURE, encoding="utf-8")
    return tmp_path


def test_create_writes_waivers_that_are_not_usable_as_is(tmp_path: Path) -> None:
    # A baseline nobody edited is a list of findings somebody silenced, and it
    # should look like one rather than quietly working.
    out = tmp_path / "b.yaml"

    result = runner.invoke(
        app, ["baseline", "create", str(_project(tmp_path)), "--output", str(out)]
    )

    assert result.exit_code == ExitCode.OK, result.output
    document = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert document["waivers"], "the scan found something, so the baseline must waive it"
    assert all("REPLACE" in w["reason"] for w in document["waivers"])
    assert all("REPLACE" in w["approved_by"] for w in document["waivers"])


def test_verify_reports_an_unreviewed_waiver_and_fails(tmp_path: Path) -> None:
    out = tmp_path / "b.yaml"
    runner.invoke(app, ["baseline", "create", str(_project(tmp_path)), "--output", str(out)])

    result = runner.invoke(app, ["baseline", "verify", str(out)])

    assert result.exit_code == ExitCode.POLICY_FAILED
    assert "unreviewed" in result.output


def test_verify_passes_once_the_waivers_are_reviewed(tmp_path: Path) -> None:
    out = tmp_path / "b.yaml"
    runner.invoke(app, ["baseline", "create", str(_project(tmp_path)), "--output", str(out)])
    document = yaml.safe_load(out.read_text(encoding="utf-8"))
    for waiver in document["waivers"]:
        waiver["reason"] = "internal tool, no external traffic"
        waiver["approved_by"] = "security@example.com"
        waiver["expires"] = "2099-01-01"
    out.write_text(yaml.safe_dump(document), encoding="utf-8")

    result = runner.invoke(app, ["baseline", "verify", str(out)])

    assert result.exit_code == ExitCode.OK, result.output


def test_verify_reports_an_expired_waiver_and_fails(tmp_path: Path) -> None:
    # The failure a team must be able to understand: the gate went red because an
    # acceptance lapsed, not because anything changed in the code.
    out = tmp_path / "b.yaml"
    out.write_text(
        yaml.safe_dump(
            {
                "version": 2,
                "waivers": [
                    {
                        "fingerprint": "abc",
                        "rule": "guardana.demo",
                        "reason": "temporary",
                        "approved_by": "someone",
                        "expires": "2020-01-01",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["baseline", "verify", str(out)])

    assert result.exit_code == ExitCode.POLICY_FAILED
    assert "expired" in result.output
    assert "no longer waives" in result.output


def test_an_expired_waiver_stops_hiding_the_finding_in_a_scan(tmp_path: Path) -> None:
    """End to end: the finding comes back and the gate goes red again."""
    project = _project(tmp_path)
    out = tmp_path / "b.yaml"
    runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])
    document = yaml.safe_load(out.read_text(encoding="utf-8"))
    for waiver in document["waivers"]:
        waiver["reason"] = "temporary"
        waiver["approved_by"] = "someone"
        waiver["expires"] = "2020-01-01"
    out.write_text(yaml.safe_dump(document), encoding="utf-8")

    still_waived = runner.invoke(
        app, ["scan", str(project), "--baseline", str(out), "--preset", "pre-training"]
    )

    assert still_waived.exit_code != ExitCode.OK, (
        "an expired waiver must stop waiving, or an accepted risk is a deleted one"
    )


def test_update_drops_waivers_for_findings_that_are_gone(tmp_path: Path) -> None:
    project = _project(tmp_path)
    out = tmp_path / "b.yaml"
    runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])
    (project / "app.py").write_text(
        "import requests\nrequests.get('https://x')\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["baseline", "update", str(project), "--file", str(out)])

    assert result.exit_code == ExitCode.OK, result.output
    assert "removed" in result.output
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["waivers"] == []


def test_update_never_adds_a_waiver_by_itself(tmp_path: Path) -> None:
    # Accepting a risk is a decision somebody makes, not something a refresh does
    # on their behalf.
    project = _project(tmp_path)
    empty = tmp_path / "b.yaml"
    empty.write_text(yaml.safe_dump({"version": 2, "waivers": []}), encoding="utf-8")

    runner.invoke(app, ["baseline", "update", str(project), "--file", str(empty)])

    assert yaml.safe_load(empty.read_text(encoding="utf-8"))["waivers"] == []


def test_verify_refuses_an_unreadable_file(tmp_path: Path) -> None:
    bad = tmp_path / "b.yaml"
    bad.write_text("waivers: [{fingerprint: 1}]\n", encoding="utf-8")

    result = runner.invoke(app, ["baseline", "verify", str(bad)])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_create_refuses_to_write_over_a_file_the_scan_read(tmp_path: Path) -> None:
    project = _project(tmp_path)
    scanned = project / "app.py"
    before = scanned.read_bytes()

    result = runner.invoke(app, ["baseline", "create", str(project), "--output", str(scanned)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    said = " ".join(result.output.split())
    assert f"error: --output {scanned} is {scanned}, which this scan read" in said
    assert "choose another --output" in said
    assert scanned.read_bytes() == before


@pytest.mark.parametrize("read", [".guardanaignore", "profile"])
def test_create_refuses_to_write_over_the_ignore_file_or_the_profile(
    tmp_path: Path, read: str
) -> None:
    (tmp_path / "project").mkdir()
    project = _project(tmp_path / "project")
    ignore = project / ".guardanaignore"
    ignore.write_text("", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: audit\n", encoding="utf-8")
    written = ignore if read == ".guardanaignore" else profile
    before = written.read_bytes()

    result = runner.invoke(
        app,
        ["baseline", "create", str(project), "--profile", str(profile), "--output", str(written)],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"{written}, which this command reads" in " ".join(result.output.split())
    assert written.read_bytes() == before


def test_create_writes_again_over_the_baseline_it_wrote_inside_the_scanned_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project(tmp_path)
    monkeypatch.chdir(tmp_path)

    first = runner.invoke(app, ["baseline", "create", "."])
    again = runner.invoke(app, ["baseline", "create", "."])

    assert first.exit_code == ExitCode.OK, first.output
    assert again.exit_code == ExitCode.OK, again.output
    written = yaml.safe_load(Path("guardana-baseline.yaml").read_text(encoding="utf-8"))
    assert written["waivers"]


def _no_space(_fd: int) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


def test_create_whose_write_fails_part_way_keeps_the_earlier_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    out = tmp_path / "b.yaml"
    first = runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])
    assert first.exit_code == ExitCode.OK, first.output
    earlier = out.read_bytes()

    monkeypatch.setattr("guardana.cli._atomic.os.fsync", _no_space)
    result = runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"could not write the baseline to {out}" in " ".join(result.output.split())
    assert out.read_bytes() == earlier


def test_update_whose_write_fails_part_way_keeps_the_approved_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    out = tmp_path / "b.yaml"
    runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])
    approved = out.read_bytes()
    (project / "app.py").write_text(
        "import requests\nrequests.get('https://x')\n", encoding="utf-8"
    )

    monkeypatch.setattr("guardana.cli._atomic.os.fsync", _no_space)
    result = runner.invoke(app, ["baseline", "update", str(project), "--file", str(out)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert out.read_bytes() == approved


def test_scan_write_baseline_whose_write_fails_part_way_keeps_the_earlier_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    out = tmp_path / "b.yaml"
    first = runner.invoke(app, ["scan", str(project), "--write-baseline", str(out)])
    assert first.exit_code == ExitCode.OK, first.output
    earlier = out.read_bytes()

    monkeypatch.setattr("guardana.cli._atomic.os.fsync", _no_space)
    result = runner.invoke(app, ["scan", str(project), "--write-baseline", str(out)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert out.read_bytes() == earlier


def test_update_keeps_and_names_a_waiver_whose_file_the_run_excluded(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "other.py").write_text("VALUE = 1\n", encoding="utf-8")
    out = tmp_path / "b.yaml"
    runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])
    created = yaml.safe_load(out.read_text(encoding="utf-8"))["waivers"]
    profile = tmp_path / "narrow.yaml"
    profile.write_text("rules:\n  paths_exclude: ['app.py']\n", encoding="utf-8")

    result = runner.invoke(
        app, ["baseline", "update", str(project), "--file", str(out), "--profile", str(profile)]
    )

    said = " ".join(result.output.split())
    assert result.exit_code == ExitCode.OK, said
    assert created
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["waivers"] == created
    assert "app.py, so whether it is fixed is unknown" in said
    assert f"{len(created)} of the kept not re-examined" in said
    assert "removed:" not in said


def test_update_keeps_a_waiver_that_names_no_rule(tmp_path: Path) -> None:
    project = _project(tmp_path)
    out = tmp_path / "b.yaml"
    out.write_text(
        yaml.safe_dump({"version": 2, "waivers": [{"fingerprint": "0123456789abcdef"}]}),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["baseline", "update", str(project), "--file", str(out)])

    assert result.exit_code == ExitCode.OK, result.output
    assert [w["fingerprint"] for w in yaml.safe_load(out.read_text("utf-8"))["waivers"]] == [
        "0123456789abcdef"
    ]
    assert "names no rule" in " ".join(result.output.split())
