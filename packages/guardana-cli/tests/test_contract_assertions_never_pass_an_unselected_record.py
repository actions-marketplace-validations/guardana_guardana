"""A contract assertion never passes over a record whose selector value nobody recorded."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


@dataclass(frozen=True)
class _Run:
    exit_code: int
    findings: list[str]
    unverified: list[str]

    @property
    def refused(self) -> bool:
        """Whether the command refused the input before grading it."""
        return self.exit_code == 3

    def answered(self, rule_id: str) -> bool:
        """Whether the rule said anything other than a silent pass."""
        return rule_id in self.findings or rule_id in self.unverified


def _analyze(
    tmp_path: Path,
    assertion: dict[str, Any],
    instrumented: list[str],
    *spans: dict[str, Any],
    profile: str | None = None,
) -> _Run:
    header = {
        "guardana_trace": 3,
        "trace_id": "t-1",
        "producer": {"name": "acme-harness", "version": "1"},
        "instrumented": instrumented,
        "terminated": True,
    }
    footer = {"guardana_trace_end": 3, "spans": len(spans)}
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        "".join(json.dumps(line) + "\n" for line in (header, *spans, footer)), encoding="utf-8"
    )
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        json.dumps({"schema_version": 1, "name": "audit", "assertions": [assertion]}),
        encoding="utf-8",
    )
    saved = tmp_path / "run.json"
    arguments = ["analyze-trace", str(trace), "--contract", str(contract)]
    arguments += ["--format", "json", "--output", str(saved)]
    if profile is not None:
        written = tmp_path / "guardana.yaml"
        written.write_text(profile, encoding="utf-8")
        arguments += ["--profile", str(written)]
    result = runner.invoke(app, arguments)
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise RuntimeError(f"analyze-trace crashed: {result.exception!r}")
    if result.exit_code == 3:
        return _Run(3, [], [])
    if result.exit_code not in (0, 1, 2) or not saved.exists():
        raise RuntimeError(f"analyze-trace saved no run (exit {result.exit_code}): {result.output}")
    document = json.loads(saved.read_text(encoding="utf-8"))
    rules_run = document["run"]["result_summary"]["rules_run"]
    rule_id = f"contract.audit.{assertion['id']}"
    if rule_id not in rules_run:
        raise RuntimeError(f"{rule_id} did not run: {rules_run}")
    return _Run(
        exit_code=result.exit_code,
        findings=[finding["rule_id"] for finding in document["findings"]],
        unverified=[finding["rule_id"] for finding in document["unverified"]],
    )


def _assertion(kind: str, **settings: object) -> dict[str, Any]:
    return {
        "id": kind.replace("_", "-"),
        "type": kind,
        "title": f"an audit {kind} assertion",
        "severity": "high",
        **settings,
    }


def _span(span_id: str, **blocks: object) -> dict[str, Any]:
    return {"span_id": span_id, "kind": "tool_execution", "name": span_id, **blocks}


def _retrieval(span_id: str, tenant: str, source: str | None) -> dict[str, Any]:
    retrieval: dict[str, Any] = {"tenant": tenant, "documents": [{"id": span_id, "tenant": tenant}]}
    if source is not None:
        retrieval["source"] = source
    return {"span_id": span_id, "kind": "retrieval", "name": "search", "retrieval": retrieval}


@dataclass(frozen=True)
class _Case:
    """One assertion kind: a record that should be graded, with and without its selector value."""

    assertion: dict[str, Any]
    instrumented: list[str]
    selected: tuple[dict[str, Any], ...]
    unlabelled: tuple[dict[str, Any], ...]


_CASES = {
    "allowed_scopes": _Case(
        _assertion("allowed_scopes", boundaries=["https://pay.example/*"], allow=["payments.*"]),
        ["delegation"],
        (
            _span(
                "s1",
                delegations=[
                    {"actor": "agent", "boundary": "https://pay.example/x", "scopes": ["admin"]}
                ],
            ),
        ),
        (_span("s1", delegations=[{"actor": "agent", "scopes": ["admin"]}]),),
    ),
    "credential_boundary": _Case(
        _assertion("credential_boundary", boundaries=["https://*.public.example/*"]),
        ["delegation"],
        (
            _span(
                "s1",
                delegations=[
                    {
                        "actor": "agent",
                        "boundary": "https://www.public.example/x",
                        "credential": {"kind": "bearer", "digest": "sha256:t"},
                    }
                ],
            ),
        ),
        (
            _span(
                "s1",
                delegations=[
                    {"actor": "agent", "credential": {"kind": "bearer", "digest": "sha256:t"}}
                ],
            ),
        ),
    ),
    "forbidden_sink": _Case(
        _assertion("forbidden_sink", sinks=["shell"], actions=["rm*"]),
        ["effects"],
        (_span("s1", effects=[{"sink": "shell", "action": "rm -r /srv", "status": "executed"}]),),
        (_span("s1", effects=[{"sink": "shell", "status": "executed"}]),),
    ),
    "approval_required": _Case(
        _assertion("approval_required", actions=["payment.*"]),
        ["approval", "effects"],
        (
            _span(
                "s1",
                effects=[{"sink": "payment", "action": "payment.refund", "status": "executed"}],
            ),
        ),
        (_span("s1", effects=[{"sink": "payment", "status": "executed"}]),),
    ),
    "tenant_boundary": _Case(
        _assertion("tenant_boundary", sources=["kb://*"]),
        ["retrieval"],
        (_retrieval("r1", "tenant-a", "kb://main"), _retrieval("r2", "tenant-b", "kb://other")),
        (_retrieval("r1", "tenant-a", "kb://main"), _retrieval("r2", "tenant-b", None)),
    ),
}


# A record that lacks the value an assertion selects on is refused or graded, never dropped.


@pytest.mark.parametrize("kind", sorted(_CASES))
def test_control_the_record_with_its_selector_value_is_a_finding(tmp_path: Path, kind: str) -> None:
    case = _CASES[kind]

    run = _analyze(tmp_path, case.assertion, case.instrumented, *case.selected)

    assert f"contract.audit.{case.assertion['id']}" in run.findings


@pytest.mark.parametrize(
    "kind",
    sorted(_CASES),
)
def test_a_record_without_its_selector_value_is_refused_or_not_a_pass(
    tmp_path: Path, kind: str
) -> None:
    case = _CASES[kind]
    rule_id = f"contract.audit.{case.assertion['id']}"

    run = _analyze(tmp_path, case.assertion, case.instrumented, *case.unlabelled)

    assert run.refused or run.answered(rule_id), run


# An assertion that could not conclude follows the documented
# `fail_on_inconclusive` switch, exactly as every other unverified check does.


def test_control_an_inconclusive_assertion_gates_under_fail_on_inconclusive(
    tmp_path: Path,
) -> None:
    assertion = _assertion(
        "allowed_scopes", boundaries=["https://pay.example/*"], allow=["payments.*"]
    )
    hop = _span("s1", delegations=[{"actor": "agent", "boundary": "https://pay.example/x"}])
    rule_id = f"contract.audit.{assertion['id']}"

    default = _analyze(tmp_path, assertion, ["delegation"], hop)
    strict = _analyze(
        tmp_path,
        assertion,
        ["delegation"],
        hop,
        profile="name: strict\nfail_on:\n  fail_on_inconclusive: true\n",
    )

    assert rule_id in default.unverified
    assert default.exit_code == 0
    assert strict.exit_code == 2
