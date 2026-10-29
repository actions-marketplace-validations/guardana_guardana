"""The native reader refuses every value the published schema refuses, generated from the schema.

A value of the wrong type read leniently is a default nobody wrote: `"reversible":
"false"` reads as "nobody said", `"sink": "Shell"` as `other`, `"terminated": "true"` as
a file that never promised a footer. Each grades a recorded execution as cleaner than it
was. The cases below are walked out of `schemas/trace-v3.schema.json` rather than listed by
hand, so a property added to the schema is covered the day it lands.
"""

import json
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from guardana.core.trace import Dimension, TraceLoadError, read_trace
from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).resolve().parents[4] / "schemas" / "trace-v3.schema.json"
_SCHEMA: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(_SCHEMA)


def _part(text: str) -> dict[str, Any]:
    return {"type": "text", "content": text}


_BLOB_PART: dict[str, Any] = {
    "type": "image",
    "id": "p1",
    "name": "chart",
    "media_type": "image/png",
    "mime_type": "image/png",
    "uri": "file:///chart.png",
    "url": "https://example.test/chart.png",
    "digest": "sha256:ab",
    "size_bytes": 12,
    "data": "aGVsbG8=",
}

_CREDENTIAL: dict[str, Any] = {
    "kind": "bearer",
    "digest": "sha256:ab",
    "value": "token",
    "audience": ["api"],
    "issuer": "idp",
    "subject": "u-1",
    "scopes": ["read"],
}

_RECORDS: dict[str, dict[str, Any]] = {
    "header": {
        "guardana_trace": 3,
        "trace_id": "t-1",
        "producer": {"name": "acme", "version": "1", "recorded_at": "2026-01-01T00:00:00+00:00"},
        "instrumented": sorted(str(d) for d in Dimension),
        "truncated": "producer_limit",
        "attributes": {"team": "payments"},
        "terminated": True,
    },
    "span": {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "pay",
        "agent": {"name": "planner", "id": "a-1"},
        "parent_span_id": "s0",
        "started_at": "2026-01-01T00:00:00+00:00",
        "ended_at": "2026-01-01T00:00:01+00:00",
        "error": "none",
        "conversation_id": "c-1",
        "model": {
            "provider": "p",
            "request_model": "m",
            "response_model": "m",
            "input_tokens": 3,
            "output_tokens": 4,
            "finish_reasons": ["stop"],
        },
        "messages": [{"role": "user", "parts": [_BLOB_PART], "finish_reason": "stop"}],
        "system_instructions": [_part("be careful")],
        "tool_offers": [
            {"name": "pay", "description": "d", "schema": "{}", "tool_type": "function"}
        ],
        "tool": {
            "name": "pay",
            "call_id": "c1",
            "arguments": "{}",
            "result": [_part("ok")],
            "status": "succeeded",
            "mutates": True,
            "server": "billing",
        },
        "retrieval": {
            "query": "q",
            "source": "kb",
            "tenant": "acme",
            "documents": [
                {
                    "id": "d1",
                    "content": [_part("doc")],
                    "source": "kb",
                    "tenant": "acme",
                    "score": 0.5,
                    "metadata": {"page": "1"},
                }
            ],
        },
        "memory": {
            "action": "write",
            "store": "m",
            "key": "k",
            "content": [_part("remembered")],
            "origin_span_id": "s0",
        },
        "handoff": {
            "from_agent": "a",
            "to_agent": "b",
            "payload": [_part("hand over")],
            "carried_scopes": ["read"],
        },
        "identity": {
            "actor": "u-1",
            "credential": dict(_CREDENTIAL),
            "claimed_resource": "api",
            "session": {"id": "sess-1", "protocol": "mcp"},
        },
        "delegations": [
            {
                "actor": "agent",
                "boundary": "api",
                "on_behalf_of": "u-1",
                "credential": dict(_CREDENTIAL),
                "scopes": ["read"],
            }
        ],
        "consents": [
            {
                "client": "c",
                "granted": True,
                "scopes": ["read"],
                "subject": "u-1",
                "recorded_at": "2026-01-01T00:00:00+00:00",
            }
        ],
        "policy_decisions": [
            {"outcome": "deny", "action": "send", "policy": "p", "rationale": "r"}
        ],
        "approvals": [
            {
                "action": "pay",
                "outcome": "granted",
                "approver": "bob",
                "approver_kind": "human",
                "requested_at": "2026-01-01T00:00:00+00:00",
                "decided_at": "2026-01-01T00:00:01+00:00",
            }
        ],
        "effects": [
            {
                "sink": "payment",
                "action": "pay",
                "target": "order/1",
                "status": "executed",
                "reversible": False,
                "detail": "d",
            }
        ],
    },
    "footer": {"guardana_trace_end": 3, "spans": 1},
}
"""One valid record per kind, holding every object the schema closes."""

_Path = tuple[str | int, ...]


def _resolved(node: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        node = _SCHEMA["$defs"][node["$ref"].rsplit("/", 1)[-1]]
    return node


def _closed_objects(
    node: dict[str, Any], value: object, where: _Path
) -> Iterator[tuple[_Path, dict[str, Any]]]:
    """Walk the schema and a record together, yielding each closed object the record holds."""
    node = _resolved(node)
    for alternative in node.get("oneOf", ()):
        if _resolved(alternative).get("type") == "object" and isinstance(value, dict):
            yield from _closed_objects(alternative, value, where)
    if isinstance(value, dict) and node.get("additionalProperties") is False:
        yield where, node
    if isinstance(value, dict):
        for name, child in node.get("properties", {}).items():
            if name in value:
                yield from _closed_objects(child, value[name], (*where, name))
    if isinstance(value, list) and value and "items" in node:
        yield from _closed_objects(node["items"], value[0], (*where, 0))


_WRONG_TYPE: dict[str, tuple[object, ...]] = {
    "string": (7, True),
    "integer": ("7", 1.5, True),
    "number": ("0.5", True),
    "boolean": ("true", 0),
    "array": ("x", {"k": "v"}),
    "object": ("x", ["x"]),
}


def _bad_values(node: dict[str, Any]) -> Iterator[tuple[str, object]]:
    """Schema-invalid values for one property: a wrong type, null and a near-miss member."""
    node = _resolved(node)
    declared = node.get("type")
    if isinstance(declared, str):
        for value in _WRONG_TYPE[declared]:
            yield f"{type(value).__name__} for {declared}", value
    if "enum" in node:
        member = str(node["enum"][0])
        yield "capitalised member", member.capitalize()
        yield "upper-cased member", member.upper()
        yield "number for an enum", 7
    if isinstance(declared, str) or "enum" in node:
        yield "null", None
    items = _resolved(node["items"]) if declared == "array" and "items" in node else None
    if items is not None and ("type" in items or "enum" in items):
        for label, bad in _bad_values(items):
            if bad is not None:
                yield f"item: {label}", [bad]
    extra = node.get("additionalProperties")
    if declared == "object" and isinstance(extra, dict) and "type" in extra:
        for label, bad in _bad_values(extra):
            yield f"value: {label}", {"k": bad}


@dataclass(frozen=True)
class _Case:
    record: str
    where: _Path
    key: str
    label: str
    value: object

    def __str__(self) -> str:
        path = ".".join(str(step) for step in (*self.where, self.key))
        return f"{self.record}:{path}={self.label}"


def _cases() -> Iterator[_Case]:
    for record, value in _RECORDS.items():
        for where, node in _closed_objects(_SCHEMA["$defs"][record], value, ()):
            for key, child in node["properties"].items():
                for label, bad in _bad_values(child):
                    yield _Case(record, where, key, label, bad)


_CASES = list(_cases())


def _with(record: dict[str, Any], case: _Case) -> dict[str, Any]:
    changed = deepcopy(record)
    node: Any = changed
    for step in case.where:
        node = node[step]
    node[case.key] = case.value
    return changed


def _write(tmp_path: Path, records: dict[str, dict[str, Any]]) -> Path:
    path = tmp_path / "trace.jsonl"
    lines = (json.dumps(records[name]) for name in ("header", "span", "footer"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _every_closed_object(node: object) -> Iterator[object]:
    if isinstance(node, dict):
        if node.get("additionalProperties") is False:
            yield node
        for child in node.values():
            yield from _every_closed_object(child)
    elif isinstance(node, list):
        for child in node:
            yield from _every_closed_object(child)


def test_the_valid_records_are_valid_and_reach_every_closed_object_of_the_schema() -> None:
    """Without this a location the records miss would drop out of the cases unnoticed."""
    for record in _RECORDS.values():
        _VALIDATOR.validate(record)
    reached = {
        json.dumps(node, sort_keys=True)
        for name, value in _RECORDS.items()
        for _, node in _closed_objects(_SCHEMA["$defs"][name], value, ())
    }
    closed = {json.dumps(node, sort_keys=True) for node in _every_closed_object(_SCHEMA["$defs"])}
    assert reached == closed


def test_the_valid_records_read(tmp_path: Path) -> None:
    read = read_trace(_write(tmp_path, _RECORDS))
    assert read.trace.spans[0].effects[0].reversible is False


@pytest.mark.parametrize("case", _CASES, ids=str)
def test_a_value_the_schema_refuses_is_refused_by_the_reader(tmp_path: Path, case: _Case) -> None:
    changed = _with(_RECORDS[case.record], case)
    assert not _VALIDATOR.is_valid(changed), "the generated value must be one the schema refuses"

    with pytest.raises(TraceLoadError) as refused:
        read_trace(_write(tmp_path, {**_RECORDS, case.record: changed}))

    message = str(refused.value)
    assert case.key in message
    if case.record == "span" and case.key != "span_id":
        assert "span 's1'" in message


def _members() -> Iterator[tuple[str, _Path, str, str]]:
    for record, value in _RECORDS.items():
        for where, node in _closed_objects(_SCHEMA["$defs"][record], value, ()):
            for key, child in node["properties"].items():
                for member in _resolved(child).get("enum", ()):
                    yield record, where, key, member


@pytest.mark.parametrize(
    ("record", "where", "key", "member"),
    list(_members()),
    ids=lambda v: ".".join(str(s) for s in v) if isinstance(v, tuple) else str(v),
)
def test_every_member_the_schema_names_is_read(
    tmp_path: Path, record: str, where: _Path, key: str, member: str
) -> None:
    changed = _with(_RECORDS[record], _Case(record, where, key, "member", member))
    _VALIDATOR.validate(changed)
    read_trace(_write(tmp_path, {**_RECORDS, record: changed}))


@pytest.mark.parametrize(
    ("where", "key"),
    [(("effects", 0), "sink"), (("policy_decisions", 0), "outcome"), (("approvals", 0), "outcome")],
)
def test_a_required_member_left_out_is_refused_rather_than_defaulted(
    tmp_path: Path, where: _Path, key: str
) -> None:
    """`other` or `unknown` is what the producer writes, never what the reader supplies."""
    span = deepcopy(_RECORDS["span"])
    node: Any = span
    for step in where:
        node = node[step]
    del node[key]
    with pytest.raises(TraceLoadError, match=rf"span 's1'.*{key}"):
        read_trace(_write(tmp_path, {**_RECORDS, "span": span}))


def test_an_optional_field_left_out_still_reads_as_unrecorded(tmp_path: Path) -> None:
    span = {"span_id": "s1", "effects": [{"sink": "shell", "action": "run"}]}
    read = read_trace(_write(tmp_path, {**_RECORDS, "span": span}))
    effect = read.trace.spans[0].effects[0]
    assert effect.reversible is None
    assert str(effect.sink) == "shell"
