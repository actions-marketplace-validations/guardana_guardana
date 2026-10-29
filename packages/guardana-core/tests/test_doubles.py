"""The stateful doubles: a backend that enforces tenancy, and a trace that is never a false record.

Every behaviour is asserted where it has to arrive: the data a call returns, the state a
later call reads, and the bytes in the trace file.
"""

import contextvars
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import yaml
from _fixtures_file import fixtures_document
from guardana.core.doubles import INSTRUMENTED, PRODUCER, Doubles, DoublesError, open_doubles
from guardana.core.fixtures import RECORD_MARKER_FIELD, FixturesError, load_fixtures
from guardana.core.trace import (
    TRACE_SCHEMA_VERSION,
    EffectStatus,
    SinkKind,
    Span,
    ToolStatus,
    TraceLoadError,
    TraceTruncation,
    read_trace,
)

_TOOLS: dict[str, dict[str, object]] = {
    "lookup_order": {"op": "get", "collection": "orders"},
    "find_orders": {"op": "search", "collection": "orders"},
    "open_order": {
        "op": "create",
        "collection": "orders",
        "sink": "sql",
        "reversible": True,
    },
    "refund_order": {
        "op": "update",
        "collection": "orders",
        "sink": "payment",
        "reversible": True,
    },
    "purge_order": {
        "op": "delete",
        "collection": "orders",
        "sink": "sql",
        "reversible": False,
    },
    "send_email": {"op": "send", "sink": "email", "reversible": False},
}


def _fixtures(tmp_path: Path, **changes: object) -> Path:
    document = fixtures_document()
    document["tools"] = _TOOLS
    document.update(changes)
    path = tmp_path / "guardana-fixtures.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _open(tmp_path: Path, **changes: object) -> tuple[Doubles, Path]:
    trace = tmp_path / "doubles.jsonl"
    return open_doubles(_fixtures(tmp_path, **changes), trace=trace), trace


def _records(trace: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]


def _spans(trace: Path) -> tuple[Span, ...]:
    return read_trace(trace).trace.spans


def _marker(tmp_path: Path, record_id: str) -> str:
    loaded = load_fixtures(tmp_path / "guardana-fixtures.yaml")
    return next(i.markers.presence for i in loaded.records if i.id == record_id)


# --- tenancy, op by op ---------------------------------------------------------------------


def test_get_finds_a_record_of_the_acting_tenant_with_its_presence_marker(tmp_path: Path) -> None:
    doubles, _ = _open(tmp_path)
    with doubles.acting_as("acme"):
        found = doubles.call("lookup_order", id="A-100")
    assert found == {
        "id": "A-100",
        "total": 40,
        "status": "open",
        RECORD_MARKER_FIELD: _marker(tmp_path, "A-100"),
    }


def test_get_does_not_see_another_tenants_record_as_row_level_security_would(
    tmp_path: Path,
) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        assert doubles.call("lookup_order", id="G-200") is None
        assert doubles.call("lookup_order", id="NOPE") is None
    doubles.close()
    first = _spans(trace)[0]
    assert first.tool is not None
    assert first.tool.status is ToolStatus.SUCCEEDED
    assert first.effects == ()


def test_search_returns_only_the_acting_tenants_records_matching_term_or_field(
    tmp_path: Path,
) -> None:
    doubles, _ = _open(tmp_path)
    loaded = load_fixtures(tmp_path / "guardana-fixtures.yaml")
    globex_term = next(i.markers.term for i in loaded.records if i.id == "G-200")
    with doubles.acting_as("acme"):
        assert doubles.call("find_orders", query="90") == []
        assert doubles.call("find_orders", query=globex_term) == []
        by_field = doubles.call("find_orders", query="OPEN")
    with doubles.acting_as("globex"):
        by_term = doubles.call("find_orders", query=globex_term.upper())
    assert [r["id"] for r in by_field] == ["A-100"]
    assert [r["id"] for r in by_term] == ["G-200"]


def test_create_adds_a_record_owned_by_the_acting_tenant(tmp_path: Path) -> None:
    doubles, _ = _open(tmp_path)
    with doubles.acting_as("acme"):
        created = doubles.call("open_order", id="A-101", total=5)
        assert doubles.call("lookup_order", id="A-101") == created == {"id": "A-101", "total": 5}
    with doubles.acting_as("globex"):
        assert doubles.call("lookup_order", id="A-101") is None


def test_create_over_an_existing_id_of_any_tenant_is_refused_and_changes_nothing(
    tmp_path: Path,
) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        assert doubles.call("open_order", id="G-200", total=1) is None
    with doubles.acting_as("globex"):
        assert doubles.call("lookup_order", id="G-200")["total"] == 90
    doubles.close()
    effect = _spans(trace)[0].effects[0]
    assert effect.status is EffectStatus.FAILED


def test_update_changes_the_acting_tenants_record(tmp_path: Path) -> None:
    doubles, _ = _open(tmp_path)
    with doubles.acting_as("acme"):
        updated = doubles.call("refund_order", id="A-100", status="refunded")
        assert updated["status"] == "refunded"
        assert doubles.call("lookup_order", id="A-100")["status"] == "refunded"


def test_update_of_another_tenants_record_finds_nothing_and_is_traced_as_failed(
    tmp_path: Path,
) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        assert doubles.call("refund_order", id="G-200", total=0) is None
    with doubles.acting_as("globex"):
        assert doubles.call("lookup_order", id="G-200")["total"] == 90
    doubles.close()
    span = _spans(trace)[0]
    assert span.tool is not None
    assert span.tool.status is ToolStatus.FAILED
    assert span.tool.mutates is False
    assert span.error == "no record orders/G-200 visible to the acting tenant"
    (effect,) = span.effects
    assert (effect.sink, effect.status, effect.reversible, effect.target) == (
        SinkKind.PAYMENT,
        EffectStatus.FAILED,
        True,
        "orders/G-200",
    )


def test_delete_removes_only_the_acting_tenants_record(tmp_path: Path) -> None:
    doubles, _ = _open(tmp_path)
    with doubles.acting_as("acme"):
        assert doubles.call("purge_order", id="G-200") is None
        assert doubles.call("purge_order", id="A-100")["id"] == "A-100"
        assert doubles.call("lookup_order", id="A-100") is None
    with doubles.acting_as("globex"):
        assert doubles.call("lookup_order", id="G-200") is not None


def test_send_changes_nothing_and_records_an_outbound_effect(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        before = doubles.call("lookup_order", id="A-100")
        assert doubles.call("send_email", to="a@example.test", body="hi") == {"sent": True}
        assert doubles.call("lookup_order", id="A-100") == before
    doubles.close()
    send = _spans(trace)[1]
    assert send.tool is not None
    assert json.loads(str(send.tool.arguments)) == {"to": "a@example.test", "body": "hi"}
    assert send.tool.mutates is True
    (effect,) = send.effects
    assert (effect.sink, effect.status, effect.reversible, effect.target) == (
        SinkKind.EMAIL,
        EffectStatus.EXECUTED,
        False,
        None,
    )


def test_a_change_is_traced_with_its_arguments_and_its_declared_effect(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        doubles.call("refund_order", id="A-100", status="refunded")
    doubles.close()
    (span,) = _spans(trace)
    assert span.name == "refund_order"
    assert span.tool is not None
    assert json.loads(str(span.tool.arguments)) == {"id": "A-100", "status": "refunded"}
    assert span.tool.status is ToolStatus.SUCCEEDED
    (effect,) = span.effects
    assert (effect.sink, effect.action, effect.status, effect.reversible) == (
        SinkKind.PAYMENT,
        "refund_order",
        EffectStatus.EXECUTED,
        True,
    )


# --- who acts ------------------------------------------------------------------------------


def test_a_call_with_no_acting_tenant_raises_before_anything_is_written(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    with pytest.raises(DoublesError, match="no acting tenant"):
        doubles.call("refund_order", id="A-100", status="refunded")
    assert trace.read_bytes() == b""
    with doubles.acting_as("acme"):
        assert doubles.call("lookup_order", id="A-100")["status"] == "open"


def test_an_undeclared_tenant_raises_before_anything_is_written(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    with pytest.raises(DoublesError, match="'initech' is not declared"):  # noqa: SIM117
        with doubles.acting_as("initech"):
            doubles.call("refund_order", id="A-100", status="refunded")
    assert trace.read_bytes() == b""


def test_concurrent_threads_acting_as_different_tenants_each_see_their_own(
    tmp_path: Path,
) -> None:
    doubles, trace = _open(tmp_path)
    rounds = 50
    barrier = threading.Barrier(2)
    seen: dict[str, list[object]] = {"acme": [], "globex": []}

    def work(tenant: str, own: str, other: str) -> None:
        with doubles.acting_as(tenant):
            barrier.wait()
            for _ in range(rounds):
                seen[tenant].append(doubles.call("lookup_order", id=own))
                seen[tenant].append(doubles.call("lookup_order", id=other))

    threads = [
        threading.Thread(target=work, args=("acme", "A-100", "G-200")),
        threading.Thread(target=work, args=("globex", "G-200", "A-100")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    doubles.close()

    for tenant, own in (("acme", "A-100"), ("globex", "G-200")):
        mine, others = seen[tenant][0::2], seen[tenant][1::2]
        assert all(isinstance(r, dict) and r["id"] == own for r in mine)
        assert others == [None] * rounds
    read = read_trace(trace)
    assert len(read.trace.spans) == 4 * rounds
    assert read.trace.truncated is None


def test_a_thread_pool_reaches_the_tenant_through_a_copied_context(tmp_path: Path) -> None:
    doubles, _ = _open(tmp_path)
    with doubles.acting_as("globex"), ThreadPoolExecutor(max_workers=1) as pool:
        context = contextvars.copy_context()
        found = pool.submit(context.run, doubles.call, "lookup_order", id="G-200").result()
    assert found["id"] == "G-200"


# --- the trace file ------------------------------------------------------------------------


def test_a_trace_file_left_from_an_earlier_run_fails_the_application_at_startup(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "doubles.jsonl"
    trace.write_text("left over\n", encoding="utf-8")
    with pytest.raises(DoublesError, match="already exists"):
        open_doubles(_fixtures(tmp_path), trace=trace)
    assert trace.read_text(encoding="utf-8") == "left over\n"


def test_the_header_is_written_with_the_first_span_in_one_write(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    assert trace.read_bytes() == b""
    writes: list[str] = []
    handle = doubles._writer._handle
    original = handle.write

    def spy(text: str) -> int:
        writes.append(text)
        return original(text)

    handle.write = spy  # type: ignore[method-assign]
    with doubles.acting_as("acme"):
        doubles.call("lookup_order", id="A-100")
    first = [json.loads(line) for line in writes[0].splitlines()]
    assert len(first) == 2
    assert first[0]["guardana_trace"] >= 1
    assert first[0]["producer"]["name"] == PRODUCER
    assert first[0]["terminated"] is True
    assert sorted(first[0]["instrumented"]) == sorted(str(d) for d in INSTRUMENTED)
    assert first[1]["name"] == "lookup_order"


def test_a_process_that_dies_after_its_first_call_leaves_a_truncated_trace_never_a_header_alone(
    tmp_path: Path,
) -> None:
    fixtures = _fixtures(tmp_path)
    called = tmp_path / "called.jsonl"
    idle = tmp_path / "idle.jsonl"
    script = (
        "import os, sys\n"
        "from guardana.core.doubles import open_doubles\n"
        "called = open_doubles(sys.argv[1], trace=sys.argv[2])\n"
        "idle = open_doubles(sys.argv[1], trace=sys.argv[3])\n"
        "with called.acting_as('acme'):\n"
        "    called.call('lookup_order', id='A-100')\n"
        "os._exit(0)\n"
    )
    command = [sys.executable, "-c", script, str(fixtures), str(called), str(idle)]
    subprocess.run(command, check=True, timeout=60)  # noqa: S603 — this interpreter, a script built here
    assert idle.read_bytes() == b""
    assert len(_records(called)) == 2
    assert read_trace(called).trace.truncated is TraceTruncation.UNTERMINATED


def test_a_process_that_exits_without_closing_still_signs_the_trace_off(tmp_path: Path) -> None:
    fixtures = _fixtures(tmp_path)
    trace = tmp_path / "exited.jsonl"
    script = (
        "import sys\n"
        "from guardana.core.doubles import open_doubles\n"
        "doubles = open_doubles(sys.argv[1], trace=sys.argv[2])\n"
        "with doubles.acting_as('acme'):\n"
        "    doubles.call('lookup_order', id='A-100')\n"
    )
    command = [sys.executable, "-c", script, str(fixtures), str(trace)]
    subprocess.run(command, check=True, timeout=60)  # noqa: S603 — this interpreter, a script built here
    assert _records(trace)[-1] == {"guardana_trace_end": TRACE_SCHEMA_VERSION, "spans": 1}
    assert read_trace(trace).trace.truncated is None


def test_closing_writes_the_footer_counting_every_span(tmp_path: Path) -> None:
    trace = tmp_path / "t.jsonl"
    with open_doubles(_fixtures(tmp_path), trace=trace) as doubles, doubles.acting_as("acme"):
        doubles.call("lookup_order", id="A-100")
        doubles.call("send_email", to="a@example.test")
    records = _records(tmp_path / "t.jsonl")
    assert records[-1] == {"guardana_trace_end": TRACE_SCHEMA_VERSION, "spans": 2}
    with pytest.raises(DoublesError, match="closed"), doubles.acting_as("acme"):
        doubles.call("lookup_order", id="A-100")


def test_doubles_never_called_leave_an_empty_file_that_no_reader_accepts(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    doubles.close()
    assert trace.read_bytes() == b""
    with pytest.raises(TraceLoadError, match="no records"):
        read_trace(trace)


def test_a_forked_process_refuses_to_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        doubles.call("lookup_order", id="A-100")
    written = trace.read_bytes()
    parent = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: parent + 1)
    with doubles.acting_as("acme"), pytest.raises(DoublesError, match="forked process"):
        doubles.call("refund_order", id="A-100", status="refunded")
    with pytest.raises(DoublesError, match="forked process"):
        doubles.close()
    doubles._at_exit()
    assert trace.read_bytes() == written
    monkeypatch.undo()
    with doubles.acting_as("acme"):
        assert doubles.call("lookup_order", id="A-100")["status"] == "open"


def test_a_call_that_cannot_be_traced_raises_changes_nothing_and_leaves_the_trace_unterminated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        doubles.call("lookup_order", id="A-100")

    def _disk_full(text: str) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(doubles._writer._handle, "write", _disk_full)
    with doubles.acting_as("acme"), pytest.raises(DoublesError, match="could not be traced"):
        doubles.call("refund_order", id="A-100", status="refunded")
    monkeypatch.undo()

    assert doubles._rows["orders"]["A-100"].fields["status"] == "open"
    with doubles.acting_as("acme"), pytest.raises(DoublesError, match="no further call"):
        doubles.call("lookup_order", id="A-100")
    doubles.close()
    assert len(_records(trace)) == 2
    assert "guardana_trace_end" not in _records(trace)[-1]
    assert read_trace(trace).trace.truncated is TraceTruncation.UNTERMINATED


# --- refused before the file exists or before a write --------------------------------------


@pytest.mark.parametrize(
    ("tool", "arguments", "message"),
    [
        ("lookup_order", {}, "takes `id`"),
        ("lookup_order", {"id": "A-100", "extra": 1}, "takes only `id`"),
        ("find_orders", {"query": ""}, "takes `query`"),
        ("refund_order", {"id": "A-100"}, "names no field"),
        ("refund_order", {"id": "A-100", RECORD_MARKER_FIELD: "X"}, RECORD_MARKER_FIELD),
        ("open_order", {"id": "A-102", "items": [1]}, "must be a string"),
        ("send_email", {"body": object()}, "JSON data"),
        ("no_such_tool", {}, "not declared under `tools:`"),
    ],
)
def test_arguments_a_tool_does_not_take_raise_before_anything_is_written(
    tmp_path: Path, tool: str, arguments: dict[str, Any], message: str
) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"), pytest.raises(DoublesError, match=message):
        doubles.call(tool, **arguments)
    assert trace.read_bytes() == b""


def test_a_sink_no_rule_reads_is_refused_before_the_trace_is_created(tmp_path: Path) -> None:
    tools = {**_TOOLS, "refund_order": {**_TOOLS["refund_order"], "sink": "payments"}}
    with pytest.raises(FixturesError, match="sink 'payments'"):
        _open(tmp_path, tools=tools)
    assert not (tmp_path / "doubles.jsonl").exists()


def test_a_fixtures_file_with_no_tools_is_refused_before_the_trace_is_created(
    tmp_path: Path,
) -> None:
    with pytest.raises(DoublesError, match="no `tools:`"):
        _open(tmp_path, tools={})
    assert not (tmp_path / "doubles.jsonl").exists()


def test_the_trace_names_the_fixtures_it_was_served_from(tmp_path: Path) -> None:
    doubles, trace = _open(tmp_path)
    with doubles.acting_as("acme"):
        doubles.call("lookup_order", id="A-100")
    doubles.close()
    loaded = load_fixtures(tmp_path / "guardana-fixtures.yaml")
    attributes = read_trace(trace).trace.attributes
    assert attributes == {"fixtures": loaded.name, "fixtures_digest": loaded.digest}
