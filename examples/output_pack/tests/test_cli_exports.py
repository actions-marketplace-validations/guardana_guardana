"""The installed CLI writes `acme-table` for `scan`, `grade` and `probe`.

`scan` and `grade` run with every outbound connection refused, and the webhook module
stays unimported: selecting a format imports that format alone. `probe` runs against a
scripted endpoint and exports a failed run, an indeterminate one and one its budget
stopped, each with its verdict and every open question.
"""

import csv
import io
import json
import re
import sys
from pathlib import Path

import pytest
from acme_doubles import ADMIT, ModelEndpoint
from guardana.cli.main import app
from typer.testing import CliRunner, Result

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SUITE = "acme.quality.answers"
_ANSWERS = {
    "How do I reset my password?": "Open Settings, then Security.",
    "Where is my invoice?": "Billing lists every invoice.",
    "Can I export my data?": "Settings has an export button.",
}

runner = CliRunner()


def _table(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


def _invoke(*arguments: str) -> tuple[Result, list[dict[str, str]]]:
    result = runner.invoke(app, [*arguments, "--format", "acme-table", *ADMIT])
    return result, _table(result.stdout) if result.stdout.startswith('"run_id"') else []


def _run_row(rows: list[dict[str, str]]) -> dict[str, str]:
    (run,) = [row for row in rows if row["outcome"] == "run"]
    return run


def _rules(directory: Path, *, expected: str = "Settings") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    header = {"guardana_dataset": 1, "name": "support", "version": "1"}
    lines = [json.dumps(header)] + [
        json.dumps({"input": question, "expect": {"contains_any": [expected]}})
        for question in _ANSWERS
    ]
    (directory / "answers.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule = {
        "id": _SUITE,
        "title": "The support bot names where to go",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "contains",
        "requires": ["chat"],
        "dataset": "./answers.jsonl",
        "expect": {"contains_any": []},
        "gate": {"min_pass_rate": 0.5, "min_sample": 3},
    }
    (directory / "answers.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return directory


def _profile(tmp_path: Path) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text("rules:\n  include: ['acme.*']\n", encoding="utf-8")
    return path


@pytest.mark.usefixtures("unimported")
def test_a_failing_scan_is_exported_with_the_network_off(
    tmp_path: Path, no_network: list[object]
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "bad.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")

    result, rows = _invoke("scan", str(tree))

    assert result.exit_code == 1, result.output
    assert rows, result.output
    assert {row["gate"] for row in rows} == {"fail"}
    assert _run_row(rows)["status"] == "exit 1"
    assert any(row["outcome"] == "finding" for row in rows)
    assert any(row["outcome"] == "ran_no_finding" for row in rows)
    assert no_network == []
    assert "acme_outputs.table" in sys.modules
    assert "acme_outputs.webhook" not in sys.modules


@pytest.mark.usefixtures("unimported")
def test_a_grade_is_exported_with_its_cases_and_suite_and_the_network_off(
    tmp_path: Path, no_network: list[object]
) -> None:
    recording = tmp_path / "answers.jsonl"
    lines = [
        {
            "guardana_recording": 1,
            "name": "support-bot",
            "version": "1",
            "verbatim": True,
            "rule": _SUITE,
        },
        *({"input": question, "reply": reply} for question, reply in _ANSWERS.items()),
    ]
    recording.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    result, rows = _invoke(
        "grade",
        str(recording),
        "--rules",
        str(_rules(tmp_path / "rules")),
        "--profile",
        str(_profile(tmp_path)),
    )

    assert result.exit_code == 0, result.output
    assert {row["gate"] for row in rows} == {"pass"}
    cases = [row for row in rows if row["outcome"] == "case"]
    assert len(cases) == 3
    assert {row["status"] for row in cases} == {"passed", "failed"}
    (suite,) = [row for row in rows if row["outcome"] == "suite"]
    assert (suite["check"], suite["status"]) == (_SUITE, "pass")
    assert not [row for row in rows if row["outcome"] == "ran_no_finding"]
    assert no_network == []
    assert "acme_outputs.webhook" not in sys.modules


def _probe(
    endpoint: ModelEndpoint, tmp_path: Path, rules: Path, *extra: str
) -> tuple[Result, list[dict[str, str]]]:
    return _invoke(
        "probe",
        "--url",
        endpoint.url,
        "--model",
        "m",
        "--rules",
        str(rules),
        "--profile",
        str(_profile(tmp_path)),
        *extra,
    )


def test_a_failed_probe_is_exported_with_its_verdict(
    model_endpoint: ModelEndpoint, tmp_path: Path
) -> None:
    model_endpoint.answer = lambda _question: "I cannot say."

    result, rows = _probe(model_endpoint, tmp_path, _rules(tmp_path / "rules"))

    assert result.exit_code == 1, result.output
    assert {row["gate"] for row in rows} == {"fail"}
    run = _run_row(rows)
    assert run["status"] == "exit 1"
    assert run["detail"] == ""
    assert run["location"].startswith(model_endpoint.url.removesuffix("/v1"))
    (suite,) = [row for row in rows if row["outcome"] == "suite"]
    assert suite["status"] == "fail"
    assert {row["status"] for row in rows if row["outcome"] == "case"} == {"failed"}
    assert len(model_endpoint.requests) == 3


def test_an_indeterminate_probe_is_exported_with_every_open_question(
    model_endpoint: ModelEndpoint, tmp_path: Path
) -> None:
    # An empty reply cannot be graded, so two of three cases are measured and the suite,
    # which needs three, declines.
    model_endpoint.answer = lambda question: "" if "invoice" in question else _ANSWERS[question]

    result, rows = _probe(model_endpoint, tmp_path, _rules(tmp_path / "rules"))

    assert result.exit_code == 2, result.output
    assert {row["gate"] for row in rows} == {"indeterminate"}
    run = _run_row(rows)
    assert run["status"] == "exit 2"
    assert run["detail"] == "nothing_verified;suite_declined;unverified"
    (suite,) = [row for row in rows if row["outcome"] == "suite"]
    assert suite["status"] == "inconclusive"
    assert suite["detail"]
    assert not [row for row in rows if row["outcome"] == "ran_no_finding"]


def test_a_probe_its_budget_stopped_is_exported_as_stopped(
    model_endpoint: ModelEndpoint, tmp_path: Path
) -> None:
    model_endpoint.answer = lambda question: _ANSWERS[question]

    result, rows = _probe(
        model_endpoint, tmp_path, _rules(tmp_path / "rules"), "--max-requests", "1"
    )

    assert result.exit_code == 6, result.output
    assert {row["gate"] for row in rows} == {"indeterminate"}
    run = _run_row(rows)
    assert run["status"] == "exit 6"
    assert run["detail"] == "stopped:budget_exhausted;nothing_verified;suite_declined"
    assert not [row for row in rows if row["outcome"] == "ran_no_finding"]
    assert len(model_endpoint.requests) == 1


def test_an_unadmitted_format_is_refused_before_the_scan(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "acme-table"])

    assert result.exit_code == 3, result.output
    assert "does not admit" in " ".join(_ANSI.sub("", result.stderr).split())
