"""Built-in trace rules never pass over a record they did not compare, and stay linear."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from guardana.core.testing import fake_llm_key
from guardana.core.trace import (
    CredentialKind,
    CredentialRef,
    Delegation,
    Dimension,
    Provenance,
    Span,
    SpanKind,
    Trace,
)
from guardana.rules.trace.credential_passthrough import CredentialPassthroughRule
from typer.testing import CliRunner

runner = CliRunner()

_ARGUMENT_LEAK = "guardana.trace.secret_in_tool_argument"
_POLICY = "guardana.trace.policy_decision_ignored"
_APPROVAL = "guardana.trace.unapproved_side_effect"
_HANDOFF = "guardana.trace.handoff_authority_expansion"
_SESSION = "guardana.trace.session_as_identity"


@dataclass(frozen=True)
class _Run:
    exit_code: int
    rules_run: list[str]
    findings: list[str]
    unverified: list[str]

    @property
    def refused(self) -> bool:
        """Whether the command refused the input before grading it."""
        return self.exit_code == 3

    def answered(self, rule_id: str) -> bool:
        """Whether the rule said anything other than a silent pass."""
        return rule_id in self.findings or rule_id in self.unverified


def _analyze(tmp_path: Path, instrumented: list[str], *spans: dict[str, Any]) -> _Run:
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
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app, ["analyze-trace", str(trace), "--format", "json", "--output", str(saved)]
    )
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise RuntimeError(f"analyze-trace crashed: {result.exception!r}")
    if result.exit_code == 3:
        return _Run(3, [], [], [])
    if result.exit_code not in (0, 1, 2) or not saved.exists():
        raise RuntimeError(f"analyze-trace saved no run (exit {result.exit_code}): {result.output}")
    document = json.loads(saved.read_text(encoding="utf-8"))
    return _Run(
        exit_code=result.exit_code,
        rules_run=document["run"]["result_summary"]["rules_run"],
        findings=[finding["rule_id"] for finding in document["findings"]],
        unverified=[finding["rule_id"] for finding in document["unverified"]],
    )


def _ran(run: _Run, rule_id: str) -> _Run:
    if rule_id not in run.rules_run:
        raise RuntimeError(f"{rule_id} did not run, so the fixture reaches nothing: {run}")
    return run


def _payment(status: str, action: str = "pay") -> dict[str, Any]:
    return {"sink": "payment", "action": action, "status": status}


# A denial and the effect it denied are compared even when one span records both.


def _denial(span_id: str, *, effect: bool, action: str | None = "pay") -> dict[str, Any]:
    decision: dict[str, Any] = {"outcome": "deny", "policy": "payments"}
    if action is not None:
        decision["action"] = action
    span: dict[str, Any] = {
        "span_id": span_id,
        "kind": "tool_execution",
        "name": "pay",
        "policy_decisions": [decision],
    }
    if effect:
        span["effects"] = [_payment("executed")]
    return span


def _effect_span(span_id: str) -> dict[str, Any]:
    return {
        "span_id": span_id,
        "kind": "tool_execution",
        "name": "pay",
        "effects": [_payment("executed")],
    }


def test_control_a_denied_payment_executed_by_a_later_span_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["policy", "effects"], _denial("s1", effect=False), _effect_span("s2"))

    assert _POLICY in run.findings


def test_a_denied_payment_executed_on_the_same_span_is_not_a_pass(tmp_path: Path) -> None:
    run = _ran(_analyze(tmp_path, ["policy", "effects"], _denial("s1", effect=True)), _POLICY)

    assert run.answered(_POLICY), run


# A delegation on a span that names no agent is never read as within the handoff.


_HANDOFF_SPAN = {
    "span_id": "h1",
    "kind": "handoff",
    "name": "handoff",
    "agent": {"name": "researcher"},
    "handoff": {"from_agent": "researcher", "to_agent": "writer", "carried_scopes": ["docs:read"]},
}


def _delegating(agent: str | None) -> dict[str, Any]:
    span: dict[str, Any] = {
        "span_id": "s2",
        "kind": "tool_execution",
        "name": "delegate",
        "delegations": [
            {"actor": "writer", "boundary": "writer->payments", "scopes": ["payments:write"]}
        ],
    }
    if agent is not None:
        span["agent"] = {"name": agent}
    return span


_LATER_ACTOR = {"span_id": "s3", "kind": "tool_execution", "name": "note", "agent": {"name": "x"}}


def test_control_the_receiver_exceeding_the_handoff_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(
        tmp_path, ["handoff", "delegation"], _HANDOFF_SPAN, _delegating("writer"), _LATER_ACTOR
    )

    assert _HANDOFF in run.findings


def test_an_unattributed_delegation_after_a_handoff_is_not_a_pass(tmp_path: Path) -> None:
    run = _ran(
        _analyze(
            tmp_path, ["handoff", "delegation"], _HANDOFF_SPAN, _delegating(None), _LATER_ACTOR
        ),
        _HANDOFF,
    )

    assert run.answered(_HANDOFF), run


# A tool execution whose arguments were not recorded is never cleared of a leaked key.


def _tool(arguments: str | None) -> dict[str, Any]:
    tool: dict[str, Any] = {"name": "fetch"}
    if arguments is not None:
        tool["arguments"] = arguments
    return {"span_id": "s1", "kind": "tool_execution", "name": "fetch", "tool": tool}


def test_control_a_key_in_recorded_arguments_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["tools"], _tool(json.dumps({"key": fake_llm_key()})))

    assert _ARGUMENT_LEAK in run.findings


def test_a_tool_call_whose_arguments_were_not_recorded_is_not_a_pass(tmp_path: Path) -> None:
    run = _ran(_analyze(tmp_path, ["tools"], _tool(None)), _ARGUMENT_LEAK)

    assert run.answered(_ARGUMENT_LEAK), run


# A policy decision that names no action is refused or graded, never passed.


_PAY = {"span_id": "s2", "kind": "tool_execution", "name": "pay", "tool": {"name": "pay"}}


def test_control_a_denied_action_performed_later_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["policy", "tools"], _denial("s1", effect=False), _PAY)

    assert _POLICY in run.findings


def test_a_denial_that_names_no_action_is_refused_or_not_a_pass(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["policy", "tools"], _denial("s1", effect=False, action=None), _PAY)

    assert run.refused or _ran(run, _POLICY).answered(_POLICY), run


# An attempted consequential effect with no approval record is weighed like an executed one.


def test_control_an_executed_payment_no_approval_covers_is_unverified(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["approval", "effects"], _effect_span("s1"))

    assert _APPROVAL in run.unverified


def test_an_attempted_payment_no_approval_covers_is_not_a_pass(tmp_path: Path) -> None:
    attempted = {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "pay",
        "effects": [_payment("attempted")],
    }

    run = _ran(_analyze(tmp_path, ["approval", "effects"], attempted), _APPROVAL)

    assert run.answered(_APPROVAL), run


def test_control_a_sql_effect_counts_once_recorded_as_irreversible(tmp_path: Path) -> None:
    dropped = {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "drop",
        "effects": [{"sink": "sql", "action": "drop", "status": "executed", "reversible": False}],
        "approvals": [{"action": "drop", "outcome": "not_requested"}],
    }

    run = _analyze(tmp_path, ["approval", "effects"], dropped)

    assert _APPROVAL in run.findings


# A producer that writes a span when it ends puts a child before its parent.


def _timed(span: dict[str, Any], start: str, end: str) -> dict[str, Any]:
    return {**span, "started_at": f"2026-01-05T{start}Z", "ended_at": f"2026-01-05T{end}Z"}


def test_a_parent_grant_written_first_but_decided_after_the_payment_is_a_finding(
    tmp_path: Path,
) -> None:
    turn = {
        "span_id": "turn",
        "kind": "agent_invocation",
        "name": "turn",
        "approvals": [
            {"action": "pay", "outcome": "granted", "decided_at": "2026-01-05T10:00:00Z"}
        ],
    }
    pay = {**_effect_span("pay"), "parent_span_id": "turn"}

    run = _analyze(
        tmp_path,
        ["approval", "effects"],
        _timed(turn, "09:00:00", "11:00:00"),
        _timed(pay, "09:00:01", "09:00:05"),
    )

    assert _APPROVAL in run.findings


def test_a_refused_tool_written_before_its_decision_span_is_not_a_pass(tmp_path: Path) -> None:
    tool = {**_PAY, "span_id": "tool", "parent_span_id": "turn"}
    turn = {**_denial("turn", effect=False), "kind": "agent_invocation", "name": "turn"}

    run = _ran(
        _analyze(
            tmp_path,
            ["policy", "tools"],
            _timed(tool, "09:00:05", "09:00:06"),
            _timed(turn, "09:00:00", "09:00:10"),
        ),
        _POLICY,
    )

    assert run.answered(_POLICY), run


def test_a_receivers_use_written_before_the_handoff_is_not_a_pass(tmp_path: Path) -> None:
    work = {
        "span_id": "work",
        "parent_span_id": "h1",
        "kind": "tool_execution",
        "name": "admin",
        "agent": {"name": "writer"},
        "delegations": [{"actor": "writer", "boundary": "writer->docs", "scopes": ["docs:admin"]}],
    }

    run = _ran(
        _analyze(
            tmp_path,
            ["handoff", "delegation"],
            _timed(work, "09:00:02", "09:00:03"),
            _timed(_HANDOFF_SPAN, "09:00:01", "09:00:30"),
            _LATER_ACTOR,
        ),
        _HANDOFF,
    )

    assert run.answered(_HANDOFF), run


def test_a_session_only_step_of_unknown_mutation_beside_a_read_is_not_a_pass(
    tmp_path: Path,
) -> None:
    delete = {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "delete_user",
        "identity": {"session": {"id": "sess-1", "protocol": "mcp"}},
        "tool": {"name": "delete_user", "arguments": "{}"},
    }
    search = {
        "span_id": "s2",
        "kind": "tool_execution",
        "name": "search",
        "tool": {"name": "search", "arguments": "{}", "mutates": False},
    }

    run = _ran(_analyze(tmp_path, ["identity", "tools"], delete, search), _SESSION)

    assert _SESSION in run.unverified, run


# The passthrough rule compares credentialed hops in time linear in the trace.


def _hops(count: int, *, shared: bool) -> Trace:
    spans = tuple(
        Span(
            span_id=f"s{index}",
            kind=SpanKind.TOOL_EXECUTION,
            name="hop",
            delegations=(
                Delegation(
                    actor=f"agent-{index}",
                    boundary=f"boundary-{index}",
                    credential=CredentialRef(
                        kind=CredentialKind.BEARER,
                        digest="sha256:shared" if shared else f"sha256:{index}",
                    ),
                ),
            ),
        )
        for index in range(count)
    )
    return Trace(
        trace_id="t-1",
        spans=spans,
        provenance=Provenance(producer="acme", source="t.jsonl", dialect="guardana"),
        instrumented=frozenset({Dimension.DELEGATION}),
    )


def _comparisons(monkeypatch: pytest.MonkeyPatch, trace: Trace) -> tuple[int, int]:
    """Grade `trace`, returning the credential reads made and the findings yielded.

    A read is a pairwise `is_same_as` or a digest lookup, so a pairwise rule and an
    indexed one are measured in one unit.
    """
    same_as = CredentialRef.is_same_as
    digest = CredentialPassthroughRule._digest
    calls = [0]

    def counted_same_as(self: CredentialRef, other: CredentialRef) -> bool:
        calls[0] += 1
        return same_as(self, other)

    def counted_digest(self: CredentialPassthroughRule, hop: Delegation) -> str:
        calls[0] += 1
        return digest(self, hop)

    monkeypatch.setattr(CredentialRef, "is_same_as", counted_same_as)
    monkeypatch.setattr(CredentialPassthroughRule, "_digest", counted_digest)
    found = list(CredentialPassthroughRule().examine(trace))
    return calls[0], len(found)


def test_control_the_counter_sees_the_comparison_that_finds_a_passthrough(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    comparisons, found = _comparisons(monkeypatch, _hops(2, shared=True))

    assert found == 1
    assert comparisons >= 1


def test_comparing_credentialed_hops_grows_linearly_with_the_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hops = 1_000
    comparisons, found = _comparisons(monkeypatch, _hops(hops, shared=False))
    if found:
        raise RuntimeError(f"distinct digests produced {found} finding(s)")

    assert comparisons <= 4 * hops, f"{comparisons} comparisons for {hops} hops"


def _counting_boundary() -> tuple[type[str], list[int]]:
    """Return a `str` type that counts every comparison and hash made on it."""
    count = [0]

    class Counted(str):
        __slots__ = ()

        def __eq__(self, other: object) -> bool:
            count[0] += 1
            return str.__eq__(self, other)

        def __ne__(self, other: object) -> bool:
            count[0] += 1
            return str.__ne__(self, other)

        def __hash__(self) -> int:
            count[0] += 1
            return str.__hash__(self)

    return Counted, count


def _undigested_hops(boundaries: list[str]) -> Trace:
    spans = tuple(
        Span(
            span_id=f"s{index}",
            kind=SpanKind.TOOL_EXECUTION,
            name="hop",
            delegations=(
                Delegation(
                    actor=f"agent-{index}",
                    boundary=boundary,
                    credential=CredentialRef(kind=CredentialKind.BEARER),
                ),
            ),
        )
        for index, boundary in enumerate(boundaries)
    )
    return Trace(
        trace_id="t-1",
        spans=spans,
        provenance=Provenance(producer="acme", source="t.jsonl", dialect="guardana"),
        instrumented=frozenset({Dimension.DELEGATION}),
    )


def test_control_the_counter_sees_the_boundaries_an_undigested_hop_is_declined_against() -> None:
    counted, count = _counting_boundary()
    trace = _undigested_hops([counted("a->b"), counted("b->c")])

    found = list(CredentialPassthroughRule().examine(trace))

    assert len(found) == 1
    assert count[0] >= 1


def test_undigested_hops_on_one_boundary_are_weighed_in_linear_time() -> None:
    hops = 1_000
    counted, count = _counting_boundary()
    trace = _undigested_hops([counted("client->gateway") for _ in range(hops)])

    found = list(CredentialPassthroughRule().examine(trace))
    if found:
        raise RuntimeError(f"hops on one boundary produced {len(found)} result(s)")

    assert count[0] <= 4 * hops, f"{count[0]} boundary operations for {hops} hops"
