"""A saved run that lost a channel, or never was one, is never read or written as a complete run."""

import json
from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from typer.testing import CliRunner

runner = CliRunner()


def _errored_run(tmp_path: Path, name: str) -> Path:
    """Save a scan that found one sink and recorded one rule that failed to load."""
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "run.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "broken.yaml").write_text("id: acme.broken\ntitle: [unclosed\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "rules:\n  include: ['guardana.supply_chain.code_execution']\n", encoding="utf-8"
    )
    saved = tmp_path / f"{name}.json"
    result = runner.invoke(
        app,
        [
            *("scan", str(source), "--profile", str(profile), "--rules", str(rules)),
            *("--format", "json", "--output", str(saved)),
        ],
    )
    document = json.loads(saved.read_text(encoding="utf-8")) if saved.exists() else {}
    if result.exit_code != ExitCode.POLICY_FAILED or len(document.get("errors", ())) != 1:
        raise RuntimeError(f"precondition: the scan should record one error: {result.output}")
    if document["run"]["result_summary"]["errors"] != 1:
        raise RuntimeError("precondition: the manifest should count the recorded error")
    return saved


def _without_errors(saved: Path) -> Path:
    document = json.loads(saved.read_text(encoding="utf-8"))
    del document["errors"]
    saved.write_text(json.dumps(document), encoding="utf-8")
    return saved


def _diff(first: Path, second: Path) -> int:
    return runner.invoke(app, ["diff", str(first), str(second)]).exit_code


def test_control_two_runs_that_recorded_an_error_are_incomplete(tmp_path: Path) -> None:
    first, second = _errored_run(tmp_path, "first"), _errored_run(tmp_path, "second")

    assert _diff(first, second) == ExitCode.INDETERMINATE


def test_runs_missing_the_errors_channel_are_never_compared_as_complete(tmp_path: Path) -> None:
    first = _without_errors(_errored_run(tmp_path, "first"))
    second = _without_errors(_errored_run(tmp_path, "second"))

    assert _diff(first, second) != ExitCode.OK


_HOLLOW: dict[str, object] = {"run": {}}
"""A document that declares a schema version and records nothing a run needs."""


def _hollow(tmp_path: Path, version: int) -> Path:
    path = tmp_path / f"hollow-{version}.json"
    path.write_text(json.dumps({"schema_version": version, **_HOLLOW}), encoding="utf-8")
    return path


def test_control_a_hollow_run_at_the_current_schema_is_refused(tmp_path: Path) -> None:
    hollow = _hollow(tmp_path, REPORT_SCHEMA_VERSION)

    result = runner.invoke(app, ["run", "migrate", str(hollow), "--output", str(tmp_path / "o")])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_control_a_hollow_run_is_not_a_readable_run(tmp_path: Path) -> None:
    hollow = _hollow(tmp_path, REPORT_SCHEMA_VERSION - 1)

    assert runner.invoke(app, ["run", "inspect", str(hollow)]).exit_code == ExitCode.INVALID_USAGE


def test_a_hollow_older_run_is_never_reported_as_migrated(tmp_path: Path) -> None:
    hollow = _hollow(tmp_path, REPORT_SCHEMA_VERSION - 1)
    output = tmp_path / "migrated.json"

    result = runner.invoke(app, ["run", "migrate", str(hollow), "--output", str(output)])

    assert result.exit_code != ExitCode.OK, result.output
    assert not output.exists()
