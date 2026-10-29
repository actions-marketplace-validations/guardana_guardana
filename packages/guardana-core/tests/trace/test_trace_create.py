"""`create_trace`: a fresh file that is empty or holds a span, never a header alone.

And `SinkMap.read_only`: a read named as one records no effect, while a read nobody named
still falls through to the default sink.
"""

import json
from pathlib import Path

import pytest
from guardana.core.trace import (
    Dimension,
    SinkKind,
    SinkMap,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    TraceLoadError,
    TraceWriteError,
    TraceWriter,
    create_trace,
    read_trace,
)

_SINKS = SinkMap(
    {"refund": SinkKind.PAYMENT}, default=SinkKind.OTHER, read_only=frozenset({"look"})
)


def _create(path: Path) -> TraceWriter:
    return create_trace(
        path,
        trace_id="t-1",
        producer="acme-app",
        instrumented=(Dimension.TOOLS, Dimension.EFFECTS),
        sinks=_SINKS,
    )


def _call(name: str, *, mutates: bool | None = None) -> Span:
    return Span(
        span_id=f"s-{name}",
        kind=SpanKind.TOOL_EXECUTION,
        name=name,
        tool=ToolExecution(name=name, status=ToolStatus.SUCCEEDED, mutates=mutates),
    )


def test_an_existing_file_is_refused_and_left_as_it_was(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    path.write_text("stale\n", encoding="utf-8")
    with pytest.raises(TraceWriteError, match="already exists"):
        _create(path)
    assert path.read_text(encoding="utf-8") == "stale\n"


def test_the_file_stays_empty_until_the_header_goes_down_with_the_first_span(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trace.jsonl"
    writer = _create(path)
    assert path.read_bytes() == b""
    writes: list[str] = []
    original = writer._handle.write

    def spy(text: str) -> int:
        writes.append(text)
        return original(text)

    writer._handle.write = spy  # type: ignore[method-assign]
    writer.span(_call("look"))
    writer.span(_call("refund", mutates=True))
    writer.finish()

    first = [json.loads(line) for line in writes[0].splitlines()]
    assert "guardana_trace" in first[0]
    assert first[1]["span_id"] == "s-look"
    assert len(first) == 2
    read = read_trace(path)
    assert read.trace.truncated is None
    assert len(read.trace.spans) == 2


def test_a_writer_finished_before_any_span_leaves_an_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    _create(path).finish()
    assert path.read_bytes() == b""
    with pytest.raises(TraceLoadError, match="no records"):
        read_trace(path)


def test_a_read_named_read_only_records_no_effect_and_an_unnamed_one_falls_through(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trace.jsonl"
    with _create(path) as writer:
        writer.span(_call("look", mutates=False))
        writer.span(_call("browse"))
    look, browse = read_trace(path).trace.spans
    assert look.effects == ()
    assert [e.sink for e in browse.effects] == [SinkKind.OTHER]


def test_a_read_only_tool_that_says_it_changed_something_is_refused(tmp_path: Path) -> None:
    writer = _create(tmp_path / "trace.jsonl")
    with pytest.raises(TraceWriteError, match="read-only"):
        writer.span(_call("look", mutates=True))
    writer.close()
