"""The native reader refuses an unknown key at every level, and the schema agrees with it.

A misspelt key below span level read leniently is a missing value: `aprover` drops who
approved, `digset` drops the credential digest, a part written `{"type": "text",
"text": ...}` carries no text at all. Each grades as "nothing recorded" rather than as
the file the producer meant to write. The published schema has always closed these
objects; the reader now does too, and the first test keeps the two from drifting apart.
"""

import json
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from guardana.core.trace import Dialect, Dimension, TraceLoadError, read_trace
from guardana.core.trace._native import OBJECT_KEYS

_SCHEMA_PATH = Path(__file__).resolve().parents[4] / "schemas" / "trace-v3.schema.json"

_HEADER: dict[str, Any] = {
    "guardana_trace": 3,
    "trace_id": "t-1",
    "producer": {"name": "acme", "version": "1", "recorded_at": "2026-01-01T00:00:00+00:00"},
    "instrumented": sorted(str(d) for d in Dimension),
}

_CREDENTIAL: dict[str, Any] = {
    "kind": "bearer",
    "digest": "sha256:ab",
    "audience": ["api"],
    "issuer": "idp",
    "subject": "u-1",
    "scopes": ["read"],
}


def _part(text: str) -> dict[str, Any]:
    return {"type": "text", "content": text}


_FULL_SPAN: dict[str, Any] = {
    "span_id": "s1",
    "kind": "tool_execution",
    "name": "pay",
    "agent": {"name": "planner", "id": "a-1"},
    "model": {"provider": "p", "request_model": "m", "finish_reasons": ["stop"]},
    "messages": [{"role": "user", "parts": [_part("hello")], "finish_reason": "stop"}],
    "system_instructions": [_part("be careful")],
    "tool_offers": [{"name": "pay", "description": "d", "schema": "{}", "tool_type": "function"}],
    "tool": {"name": "pay", "call_id": "c1", "arguments": "{}", "result": [_part("ok")]},
    "retrieval": {
        "query": "q",
        "source": "kb",
        "tenant": "acme",
        "documents": [{"id": "d1", "content": [_part("doc")], "tenant": "acme"}],
    },
    "memory": {"action": "write", "store": "m", "key": "k", "content": [_part("remembered")]},
    "handoff": {
        "from_agent": "a",
        "to_agent": "b",
        "payload": [_part("hand over")],
        "carried_scopes": [],
    },
    "identity": {
        "actor": "u-1",
        "credential": dict(_CREDENTIAL),
        "claimed_resource": "api",
        "session": {"id": "sess-1", "protocol": "mcp"},
    },
    "delegations": [{"actor": "agent", "boundary": "api", "credential": dict(_CREDENTIAL)}],
    "consents": [{"client": "c", "granted": True, "scopes": ["read"], "subject": "u-1"}],
    "policy_decisions": [{"outcome": "deny", "action": "send", "policy": "p"}],
    "approvals": [{"action": "pay", "outcome": "granted", "approver": "bob"}],
    "effects": [{"sink": "payment", "action": "pay", "status": "executed"}],
}

_SPAN_LEVELS: dict[str, tuple[str | int, ...]] = {
    "span.agent": ("agent",),
    "span.model": ("model",),
    "message": ("messages", 0),
    "part in a message": ("messages", 0, "parts", 0),
    "part in system_instructions": ("system_instructions", 0),
    "span.tool_offers[]": ("tool_offers", 0),
    "span.tool": ("tool",),
    "part in a tool result": ("tool", "result", 0),
    "span.retrieval": ("retrieval",),
    "span.retrieval.documents[]": ("retrieval", "documents", 0),
    "part in a retrieved document": ("retrieval", "documents", 0, "content", 0),
    "span.memory": ("memory",),
    "part in a memory operation": ("memory", "content", 0),
    "span.handoff": ("handoff",),
    "part in a handoff payload": ("handoff", "payload", 0),
    "span.identity": ("identity",),
    "session": ("identity", "session"),
    "credential of an identity": ("identity", "credential"),
    "credential of a delegation": ("delegations", 0, "credential"),
    "span.delegations[]": ("delegations", 0),
    "span.consents[]": ("consents", 0),
    "span.policy_decisions[]": ("policy_decisions", 0),
    "span.approvals[]": ("approvals", 0),
    "span.effects[]": ("effects", 0),
}


def _write(tmp_path: Path, *records: object) -> Path:
    path = tmp_path / "trace.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def _with_key(span: dict[str, Any], where: tuple[str | int, ...], key: str) -> dict[str, Any]:
    changed = deepcopy(span)
    node: Any = changed
    for step in where:
        node = node[step]
    node[key] = "x"
    return changed


def _closed_objects(node: object, where: str) -> Iterator[tuple[str, frozenset[str]]]:
    """Every object the schema closes with `additionalProperties: false`, by its place."""
    if not isinstance(node, dict):
        return
    if "properties" in node and node.get("additionalProperties") is False:
        yield where, frozenset(node["properties"])
    for name, child in node.get("properties", {}).items():
        yield from _closed_objects(child, f"{where}.{name}")
    if "items" in node:
        yield from _closed_objects(node["items"], f"{where}[]")
    for alternative in node.get("oneOf", ()):
        yield from _closed_objects(alternative, where)


def test_every_closed_schema_object_has_exactly_the_keys_the_reader_allows() -> None:
    """A key added to the reader or to the schema fails here until both have it."""
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    closed = dict(
        item for name, node in schema["$defs"].items() for item in _closed_objects(node, name)
    )
    assert closed == dict(OBJECT_KEYS)


def test_a_span_using_every_level_with_known_keys_reads(tmp_path: Path) -> None:
    span = read_trace(_write(tmp_path, _HEADER, _FULL_SPAN)).trace.spans[0]
    assert span.messages[0].text() == "hello"
    assert span.identity is not None
    assert span.identity.credential is not None
    assert span.identity.credential.digest == "sha256:ab"
    assert span.approvals[0].approver == "bob"


@pytest.mark.parametrize("level", sorted(_SPAN_LEVELS))
def test_an_unknown_key_at_any_span_level_is_refused(tmp_path: Path, level: str) -> None:
    span = _with_key(_FULL_SPAN, _SPAN_LEVELS[level], "zz_unknown")
    with pytest.raises(TraceLoadError, match="zz_unknown"):
        read_trace(_write(tmp_path, _HEADER, span))


@pytest.mark.parametrize(
    ("where", "misspelt"),
    [
        (("approvals", 0), "aprover"),
        (("policy_decisions", 0), "actoin"),
        (("identity",), "scoeps"),
        (("identity", "credential"), "digset"),
        (("tool",), "argz"),
        (("messages", 0, "parts", 0), "text"),
    ],
)
def test_a_misspelt_nested_field_is_refused_rather_than_read_as_absent(
    tmp_path: Path, where: tuple[str | int, ...], misspelt: str
) -> None:
    span = _with_key(_FULL_SPAN, where, misspelt)
    with pytest.raises(TraceLoadError, match=misspelt):
        read_trace(_write(tmp_path, _HEADER, span))


def test_the_refusal_names_the_span_and_the_keys_it_would_have_accepted(tmp_path: Path) -> None:
    span = _with_key(_FULL_SPAN, ("messages", 0, "parts", 0), "text")
    with pytest.raises(TraceLoadError, match=r"span 's1'.*known keys are .*content"):
        read_trace(_write(tmp_path, _HEADER, span))


def test_an_unknown_producer_key_in_the_header_is_refused(tmp_path: Path) -> None:
    header = {**_HEADER, "producer": {"name": "acme", "verison": "1"}}
    with pytest.raises(TraceLoadError, match="verison"):
        read_trace(_write(tmp_path, header, {"span_id": "s1"}))


def test_a_native_message_spelling_its_parts_as_content_is_refused(tmp_path: Path) -> None:
    """`content` is the OpenTelemetry fallback; the native schema names the list `parts`."""
    span = {**_FULL_SPAN, "messages": [{"role": "user", "content": [_part("hello")]}]}
    with pytest.raises(TraceLoadError, match="content"):
        read_trace(_write(tmp_path, _HEADER, span))


def test_the_opentelemetry_dialect_stays_tolerant_of_extra_message_and_part_keys(
    tmp_path: Path,
) -> None:
    """An OTel span carries attributes from every domain it touches; extra keys are ordinary."""
    record = {
        "name": "chat",
        "context": {"trace_id": "tr-1", "span_id": "sp-1"},
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.input.messages": [
                {
                    "role": "user",
                    "vendor_extra": 1,
                    "parts": [{"type": "text", "content": "hi", "vendor_extra": 2}],
                }
            ],
        },
    }
    read = read_trace(_write(tmp_path, record), Dialect.OTEL)
    assert read.trace.spans[0].messages[0].text() == "hi"


_OBJECTS: dict[str, tuple[str | int, ...]] = {
    level: where for level, where in _SPAN_LEVELS.items() if level != "session"
}
"""Every place the schema holds an object, but a session, which may be a bare id."""

_PARTS: dict[str, tuple[str | int, ...]] = {
    level: where for level, where in _SPAN_LEVELS.items() if level.startswith("part in")
}

_LISTS: dict[str, tuple[str | int, ...]] = {
    "messages": ("messages",),
    "parts of a message": ("messages", 0, "parts"),
    "system_instructions": ("system_instructions",),
    "tool_offers": ("tool_offers",),
    "a tool result": ("tool", "result"),
    "retrieval documents": ("retrieval", "documents"),
    "content of a retrieved document": ("retrieval", "documents", 0, "content"),
    "memory content": ("memory", "content"),
    "a handoff payload": ("handoff", "payload"),
    "delegations": ("delegations",),
    "consents": ("consents",),
    "policy_decisions": ("policy_decisions",),
    "approvals": ("approvals",),
    "effects": ("effects",),
    "model finish_reasons": ("model", "finish_reasons"),
    "handoff carried_scopes": ("handoff", "carried_scopes"),
    "credential audience": ("identity", "credential", "audience"),
    "credential scopes": ("identity", "credential", "scopes"),
    "delegation scopes": ("delegations", 0, "scopes"),
    "consent scopes": ("consents", 0, "scopes"),
}

_STRING_LISTS = {
    level: where
    for level, where in _LISTS.items()
    if where[-1] in {"finish_reasons", "carried_scopes", "audience", "scopes"}
}


def _replaced(span: dict[str, Any], where: tuple[str | int, ...], value: object) -> dict[str, Any]:
    changed = deepcopy(span)
    node: Any = changed
    for step in where[:-1]:
        node = node[step]
    node[where[-1]] = value
    return changed


@pytest.mark.parametrize("level", sorted(_OBJECTS))
def test_a_bare_string_where_the_schema_holds_an_object_is_refused(
    tmp_path: Path, level: str
) -> None:
    """A string read as an empty record, or as a text part, is a record nobody wrote."""
    span = _replaced(_FULL_SPAN, _OBJECTS[level], "hello")
    with pytest.raises(TraceLoadError, match=r"span 's1'.*must be a JSON object"):
        read_trace(_write(tmp_path, _HEADER, span))


@pytest.mark.parametrize("level", sorted(_LISTS))
def test_a_bare_value_where_the_schema_holds_a_list_is_refused(tmp_path: Path, level: str) -> None:
    span = _replaced(_FULL_SPAN, _LISTS[level], "hello")
    with pytest.raises(TraceLoadError, match=r"span 's1'.*must be a JSON array"):
        read_trace(_write(tmp_path, _HEADER, span))


@pytest.mark.parametrize("level", sorted(_STRING_LISTS))
def test_a_list_of_strings_holding_another_value_is_refused(tmp_path: Path, level: str) -> None:
    span = _replaced(_FULL_SPAN, _STRING_LISTS[level], ["read", 7])
    with pytest.raises(TraceLoadError, match=r"span 's1'.*array of strings"):
        read_trace(_write(tmp_path, _HEADER, span))


def test_a_misspelt_key_in_a_list_written_as_one_object_is_refused(tmp_path: Path) -> None:
    """Read as absent, the object's misspelt key would never be seen."""
    span = {**_FULL_SPAN, "approvals": {"action": "pay", "outcome": "granted", "aprover": "x"}}
    with pytest.raises(TraceLoadError, match=r"span 's1'.*approvals must be a JSON array"):
        read_trace(_write(tmp_path, _HEADER, span))


def test_document_metadata_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    span = _replaced(_FULL_SPAN, ("retrieval", "documents", 0, "metadata"), ["k"])
    with pytest.raises(TraceLoadError, match=r"span 's1'.*metadata must be a JSON object"):
        read_trace(_write(tmp_path, _HEADER, span))


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("instrumented", "messages", "instrumented must be a JSON array"),
        ("attributes", ["a"], "attributes must be a JSON object"),
        ("producer", "acme", "producer must be a JSON object"),
    ],
)
def test_a_header_field_of_the_wrong_shape_is_refused(
    tmp_path: Path, key: str, value: object, message: str
) -> None:
    with pytest.raises(TraceLoadError, match=message):
        read_trace(_write(tmp_path, {**_HEADER, key: value}, {"span_id": "s1"}))


@pytest.mark.parametrize("level", sorted(_PARTS))
def test_a_part_without_a_type_is_refused(tmp_path: Path, level: str) -> None:
    span = _replaced(_FULL_SPAN, _PARTS[level], {"content": "hello"})
    with pytest.raises(TraceLoadError, match=r"span 's1'.*`type`"):
        read_trace(_write(tmp_path, _HEADER, span))


def test_a_session_may_be_a_bare_id_or_an_object_and_nothing_else(tmp_path: Path) -> None:
    as_id = _replaced(_FULL_SPAN, ("identity", "session"), "sess-1")
    as_number = _replaced(_FULL_SPAN, ("identity", "session"), 7)

    span = read_trace(_write(tmp_path, _HEADER, as_id)).trace.spans[0]

    assert span.identity is not None
    assert span.identity.session is not None
    assert span.identity.session.id == "sess-1"
    with pytest.raises(TraceLoadError, match=r"span 's1'.*session"):
        read_trace(_write(tmp_path, _HEADER, as_number))
