"""The doubles' trace through `guardana analyze-trace`: empty is refused, one call is graded."""

import json
from pathlib import Path

import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.doubles import open_doubles
from typer.testing import CliRunner, Result

runner = CliRunner()

_KEY = "sk-proj-" + "A" * 24


def _fixtures(tmp_path: Path) -> Path:
    document = {
        "schema_version": 1,
        "name": "support-bot",
        "data": "synthetic",
        "tenants": {
            "acme": {"api_key_env": "ACME_KEY"},
            "globex": {"api_key_env": "GLOBEX_KEY"},
        },
        "records": {
            "orders": [
                {"id": "A-100", "tenant": "acme", "fields": {"total": 40}},
                {"id": "G-200", "tenant": "globex", "fields": {"total": 90}},
            ]
        },
        "tools": {"send_email": {"op": "send", "sink": "email", "reversible": False}},
    }
    path = tmp_path / "guardana-fixtures.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _analyze(trace: Path, tmp_path: Path) -> tuple[Result, dict[str, object]]:
    output = tmp_path / "run.json"
    result = runner.invoke(
        app, ["analyze-trace", str(trace), "--format", "json", "--output", str(output)]
    )
    saved: dict[str, object] = (
        json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
    )
    return result, saved


def test_doubles_that_were_never_called_leave_a_trace_analyze_trace_refuses(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "doubles.jsonl"
    open_doubles(_fixtures(tmp_path), trace=trace).close()

    result, _ = _analyze(trace, tmp_path)

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "no records" in result.output


def test_a_trace_of_one_call_loads_and_its_tool_rules_grade_it(tmp_path: Path) -> None:
    trace = tmp_path / "doubles.jsonl"
    with open_doubles(_fixtures(tmp_path), trace=trace) as doubles, doubles.acting_as("acme"):
        doubles.call("send_email", to="a@example.test", body="your order shipped")

    result, saved = _analyze(trace, tmp_path)

    assert result.exit_code == ExitCode.OK, result.output
    run = saved["run"]
    assert isinstance(run, dict)
    assert "guardana.trace.secret_in_tool_argument" in run["result_summary"]["rules_run"]


def test_a_secret_the_application_passes_to_a_double_is_a_finding(tmp_path: Path) -> None:
    trace = tmp_path / "doubles.jsonl"
    with open_doubles(_fixtures(tmp_path), trace=trace) as doubles, doubles.acting_as("acme"):
        doubles.call("send_email", to="a@example.test", body=f"key {_KEY}")

    result, saved = _analyze(trace, tmp_path)

    assert result.exit_code == ExitCode.POLICY_FAILED
    findings = saved["findings"]
    assert isinstance(findings, list)
    assert [f["rule_id"] for f in findings] == ["guardana.trace.secret_in_tool_argument"]
    assert _KEY not in json.dumps(saved)
