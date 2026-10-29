"""`analyze-trace` stops on a native value of the wrong type or outside its enum (exit `3`).

Each case below is a file that graded clean while the same file written with the
schema's own spelling grades as a finding or as indeterminate. Read leniently, the
wrong spelling turned a forbidden shell into `other`, an irreversible effect into one
nobody described, and a promised footer into no promise at all.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner, Result

runner = CliRunner()

_NO_SHELL = """
schema_version: 1
name: noshell
assertions:
  - id: no-shell
    type: forbidden_sink
    title: Never a shell
    severity: critical
    sinks: [shell]
"""


def _header(*instrumented: str) -> dict[str, Any]:
    return {
        "guardana_trace": 3,
        "trace_id": "t-1",
        "producer": {"name": "acme"},
        "instrumented": list(instrumented),
        "terminated": True,
    }


def _footer(spans: int) -> dict[str, Any]:
    return {"guardana_trace_end": 3, "spans": spans}


def _tool_span(span_id: str, name: str, effect: dict[str, Any]) -> dict[str, Any]:
    return {
        "span_id": span_id,
        "kind": "tool_execution",
        "name": name,
        "tool": {"name": name, "status": "succeeded"},
        "effects": [{"action": name, "status": "executed", **effect}],
    }


def _shell(sink: str) -> list[dict[str, Any]]:
    return [
        _header("tools", "effects"),
        _tool_span("s1", "run", {"sink": sink, "reversible": False}),
        _footer(1),
    ]


def _denied_then_executed(reversible: object) -> list[dict[str, Any]]:
    approval = {
        "action": "db.drop",
        "outcome": "denied",
        "approver": "ops",
        "approver_kind": "human",
    }
    return [
        _header("tools", "effects", "approval"),
        {"span_id": "s1", "kind": "agent_invocation", "name": "ask", "approvals": [approval]},
        _tool_span("s2", "db.drop", {"sink": "sql", "reversible": reversible}),
        _footer(2),
    ]


def _unterminated(terminated: object) -> list[dict[str, Any]]:
    header = {**_header("tools", "effects"), "terminated": terminated}
    return [header, _tool_span("s1", "lookup", {"sink": "sql", "reversible": True})]


def _run(tmp_path: Path, records: list[dict[str, Any]]) -> Result:
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    contract = tmp_path / "contract.yaml"
    contract.write_text(_NO_SHELL, encoding="utf-8")
    return runner.invoke(app, ["analyze-trace", str(trace), "--contract", str(contract)])


@pytest.mark.parametrize(
    ("valid", "misspelt", "graded", "field"),
    [
        (_shell("shell"), _shell("Shell"), ExitCode.POLICY_FAILED, "sink"),
        (
            _denied_then_executed(False),
            _denied_then_executed("false"),
            ExitCode.POLICY_FAILED,
            "reversible",
        ),
        (_unterminated(True), _unterminated("true"), ExitCode.INDETERMINATE, "terminated"),
    ],
    ids=["a capitalised sink", "a quoted reversible", "a quoted terminated"],
)
def test_a_value_spelt_outside_the_schema_stops_the_read_rather_than_grading_clean(
    tmp_path: Path,
    valid: list[dict[str, Any]],
    misspelt: list[dict[str, Any]],
    graded: ExitCode,
    field: str,
) -> None:
    assert _run(tmp_path, valid).exit_code == graded

    result = _run(tmp_path, misspelt)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert field in " ".join(result.output.split())
