"""Reading, converting and inspecting a trace never hides a record the reader lost."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from guardana.core.testing import fake_llm_key
from guardana.core.trace import Dimension, Provenance, Span, SpanKind, ToolExecution, Trace
from guardana.core.trace.bridge import as_trajectory
from guardana.core.trace.model import TraceTruncation
from typer.testing import CliRunner

runner = CliRunner()

_ARGUMENT_LEAK = "guardana.trace.secret_in_tool_argument"
_TENANT = "guardana.trace.cross_tenant_retrieval"
_EXIT_CODES = frozenset({0, 1, 2, 3})


@dataclass(frozen=True)
class _Run:
    exit_code: int
    rules_run: list[str]
    findings: list[str]
    unverified: list[str]
    errors: int

    def answered(self, rule_id: str) -> bool:
        """Whether the rule said anything other than a silent pass."""
        return rule_id in self.findings or rule_id in self.unverified


def _analyze(tmp_path: Path, trace: Path, *extra: str, name: str = "run") -> _Run:
    saved = tmp_path / f"{name}.json"
    result = runner.invoke(
        app,
        ["analyze-trace", str(trace), "--format", "json", "--output", str(saved), *extra],
    )
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise RuntimeError(f"analyze-trace crashed: {result.exception!r}")
    if result.exit_code not in _EXIT_CODES - {3} or not saved.exists():
        raise RuntimeError(f"analyze-trace saved no run (exit {result.exit_code}): {result.output}")
    document = json.loads(saved.read_text(encoding="utf-8"))
    return _Run(
        exit_code=result.exit_code,
        rules_run=document["run"]["result_summary"]["rules_run"],
        findings=[finding["rule_id"] for finding in document["findings"]],
        unverified=[finding["rule_id"] for finding in document["unverified"]],
        errors=len(document["errors"]),
    )


def _exit_of(trace: Path) -> int:
    result = runner.invoke(app, ["analyze-trace", str(trace), "--format", "json"])
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise RuntimeError(f"analyze-trace crashed: {result.exception!r}")
    if result.exit_code not in _EXIT_CODES:
        raise RuntimeError(f"analyze-trace exited {result.exit_code}: {result.output}")
    return result.exit_code


def _native(
    tmp_path: Path,
    instrumented: list[str],
    *records: dict[str, Any] | str,
    terminated: bool = False,
) -> Path:
    """Write a native trace; a string record is written verbatim as a malformed line."""
    header: dict[str, Any] = {
        "guardana_trace": 3,
        "trace_id": "t-1",
        "producer": {"name": "acme-harness", "version": "1"},
        "instrumented": instrumented,
    }
    lines = [json.dumps(header)]
    lines += [record if isinstance(record, str) else json.dumps(record) for record in records]
    if terminated:
        header["terminated"] = True
        lines[0] = json.dumps(header)
        lines.append(json.dumps({"guardana_trace_end": 3, "spans": len(records)}))
    path = tmp_path / "trace.jsonl"
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def _otel(tmp_path: Path, *spans: dict[str, Any]) -> Path:
    path = tmp_path / "otel.jsonl"
    path.write_text("".join(json.dumps(span) + "\n" for span in spans), encoding="utf-8")
    return path


def _tool_span(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "http_request",
        "tool": {"name": "http_request", "arguments": json.dumps(arguments)},
    }


def _otel_tool(span_id: str, arguments: dict[str, Any], **extra: object) -> dict[str, Any]:
    return {
        "traceId": "t-otel",
        "spanId": span_id,
        "name": "execute_tool http_request",
        "attributes": {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": "http_request",
            "gen_ai.tool.call.arguments": json.dumps(arguments),
        },
        **extra,
    }


def _keyed() -> dict[str, Any]:
    return {"url": "https://api.invalid/v1", "headers": {"x-api-key": fake_llm_key()}}


_PLAIN = {"url": "https://api.invalid/v1"}


# `--write-trace` keeps a partially read trace incomplete in the trace it writes.


def test_control_a_converted_clean_trace_grades_the_same(tmp_path: Path) -> None:
    trace = _native(tmp_path, ["tools"], _tool_span(_PLAIN), terminated=True)
    converted = tmp_path / "native.jsonl"

    first = _analyze(tmp_path, trace, "--write-trace", str(converted))

    assert first.exit_code == 0
    assert _ARGUMENT_LEAK in first.rules_run
    assert _exit_of(converted) == 0


def test_converting_a_trace_with_an_unreadable_record_keeps_it_incomplete(tmp_path: Path) -> None:
    trace = _native(tmp_path, ["tools"], _tool_span(_PLAIN), "{torn", terminated=True)
    converted = tmp_path / "native.jsonl"

    first = _analyze(tmp_path, trace, "--write-trace", str(converted))
    if first.exit_code != 2 or first.errors == 0:
        raise RuntimeError(f"the source trace was not read in part: {first}")
    if not converted.exists():
        return

    assert _exit_of(converted) != 0, "the converted trace grades as a complete, clean execution"


# A message attribute on an OpenTelemetry span never hides the message events beside it.


def _chat(*, with_user_attribute: bool) -> dict[str, Any]:
    attributes: dict[str, Any] = {"gen_ai.operation.name": "chat"}
    if with_user_attribute:
        attributes["gen_ai.input.messages"] = [
            {"role": "user", "parts": [{"type": "text", "content": "fetch the report"}]}
        ]
    call = {
        "id": "c1",
        "function": {"name": "http_request", "arguments": json.dumps(_keyed())},
    }
    return {
        "traceId": "t-otel",
        "spanId": "chat-1",
        "name": "chat",
        "attributes": attributes,
        "events": [{"name": "gen_ai.assistant.message", "attributes": {"tool_calls": [call]}}],
    }


def test_control_a_tool_call_event_with_a_secret_is_a_finding(tmp_path: Path) -> None:
    trace = _otel(tmp_path, _chat(with_user_attribute=False), _otel_tool("t1", _PLAIN))

    run = _analyze(tmp_path, trace)

    assert _ARGUMENT_LEAK in run.findings


def test_a_message_attribute_does_not_hide_the_tool_call_event_beside_it(tmp_path: Path) -> None:
    trace = _otel(tmp_path, _chat(with_user_attribute=True), _otel_tool("t1", _PLAIN))

    run = _analyze(tmp_path, trace)
    if _ARGUMENT_LEAK not in run.rules_run:
        raise RuntimeError(f"the secret rule did not run: {run}")

    assert _ARGUMENT_LEAK in run.findings, run


# A span whose exporter dropped attributes or events is never read as complete.


@pytest.mark.parametrize("counter", ["droppedAttributesCount", "droppedEventsCount"])
def test_control_a_span_carrying_a_drop_counter_is_still_read(tmp_path: Path, counter: str) -> None:
    trace = _otel(tmp_path, _otel_tool("t1", _keyed(), **{counter: 1}))

    run = _analyze(tmp_path, trace)

    assert _ARGUMENT_LEAK in run.findings


@pytest.mark.parametrize("counter", ["droppedAttributesCount", "droppedEventsCount"])
def test_a_span_whose_exporter_dropped_content_is_not_a_pass(tmp_path: Path, counter: str) -> None:
    trace = _otel(tmp_path, _otel_tool("t1", _PLAIN, **{counter: 1}))

    run = _analyze(tmp_path, trace)
    if _ARGUMENT_LEAK not in run.rules_run:
        raise RuntimeError(f"the secret rule did not run: {run}")

    assert run.answered(_ARGUMENT_LEAK) or run.errors, run


# A native trace that holds no spans is never graded as clean.


def test_control_a_single_recorded_tool_call_is_graded(tmp_path: Path) -> None:
    trace = _native(tmp_path, ["tools"], _tool_span(_keyed()))

    assert _exit_of(trace) == 1


def test_a_native_trace_with_no_spans_is_not_a_pass(tmp_path: Path) -> None:
    trace = _native(tmp_path, ["tools"])

    assert _exit_of(trace) != 0


# A tool call carried only in a message is scanned for secrets like one on a tool span.


def _chat_calling(arguments: dict[str, Any]) -> dict[str, Any]:
    output = [
        {
            "role": "assistant",
            "parts": [
                {"type": "tool_call", "id": "c1", "name": "http_request", "arguments": arguments}
            ],
        }
    ]
    return {
        "traceId": "t-otel",
        "spanId": "chat-1",
        "name": "chat",
        "attributes": {"gen_ai.operation.name": "chat", "gen_ai.output.messages": output},
    }


_SEARCH = {
    "traceId": "t-otel",
    "spanId": "r1",
    "name": "retrieval",
    "attributes": {"gen_ai.operation.name": "retrieval", "gen_ai.data_source.id": "kb-main"},
}


def test_control_a_message_tool_call_is_scanned_once_tools_are_licensed(tmp_path: Path) -> None:
    trace = _otel(tmp_path, _chat_calling(_keyed()), _otel_tool("t1", _PLAIN))

    run = _analyze(tmp_path, trace)

    assert _ARGUMENT_LEAK in run.findings


def test_a_secret_in_a_message_only_tool_call_is_a_finding(tmp_path: Path) -> None:
    trace = _otel(tmp_path, _chat_calling(_keyed()), _SEARCH)

    run = _analyze(tmp_path, trace)

    assert _ARGUMENT_LEAK in run.findings, run
    assert run.exit_code == 1, run


# An OpenTelemetry retrieval that recorded no documents is never read as an empty search.


def test_control_a_document_of_another_tenant_is_a_finding(tmp_path: Path) -> None:
    retrieval = {
        "span_id": "r1",
        "kind": "retrieval",
        "name": "search",
        "retrieval": {
            "source": "kb-main",
            "tenant": "tenant-a",
            "documents": [{"id": "d1", "tenant": "tenant-b"}],
        },
    }
    trace = _native(tmp_path, ["retrieval"], retrieval)

    run = _analyze(tmp_path, trace)

    assert _TENANT in run.findings


def test_a_retrieval_that_recorded_no_results_is_not_a_tenant_pass(tmp_path: Path) -> None:
    trace = _otel(tmp_path, _SEARCH)

    run = _analyze(tmp_path, trace)

    assert _TENANT not in run.rules_run or run.answered(_TENANT), run


# The trajectory adapter keeps the records the reader could not interpret, as it keeps a truncation.


def _shell_trace(*, unreadable: int = 0, truncated: TraceTruncation | None = None) -> Trace:
    return Trace(
        trace_id="t-1",
        spans=(
            Span(
                span_id="s1",
                kind=SpanKind.TOOL_EXECUTION,
                name="lookup",
                tool=ToolExecution(name="lookup", arguments="{}"),
            ),
        ),
        provenance=Provenance(producer="acme", source="t.jsonl", dialect="guardana"),
        instrumented=frozenset({Dimension.TOOLS}),
        truncated=truncated,
        unreadable=unreadable,
    )


def test_control_a_truncated_trace_becomes_a_truncated_trajectory() -> None:
    trajectory = as_trajectory(_shell_trace(truncated=TraceTruncation.UNTERMINATED))

    assert trajectory.truncated is not None


def test_a_trace_with_an_unreadable_record_becomes_an_incomplete_trajectory() -> None:
    trajectory = as_trajectory(_shell_trace(unreadable=1))

    assert trajectory.truncated is not None, trajectory


# `trace inspect` says when a record could not be read.


def _partly_readable(tmp_path: Path) -> Path:
    return _native(tmp_path, ["tools"], _tool_span(_PLAIN), "{torn", terminated=True)


def test_control_analyze_trace_reports_the_unreadable_record(tmp_path: Path) -> None:
    run = _analyze(tmp_path, _partly_readable(tmp_path))

    assert run.errors == 1


def test_trace_inspect_says_a_record_could_not_be_read(tmp_path: Path) -> None:
    trace = _partly_readable(tmp_path)

    as_json = runner.invoke(app, ["trace", "inspect", str(trace), "--format", "json"])
    as_text = runner.invoke(app, ["trace", "inspect", str(trace)])
    if as_json.exit_code != 0 or as_text.exit_code != 0:
        raise RuntimeError(f"trace inspect failed: {as_json.output} {as_text.output}")
    document = json.loads(as_json.output)

    assert any("unreadable" in key for key in document), document
    assert "unreadable" in as_text.output or "could not be read" in as_text.output, as_text.output
