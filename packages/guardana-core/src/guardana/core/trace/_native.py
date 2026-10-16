"""The dialect Guardana defines: OpenTelemetry's message shape plus the named extensions.

Strict about keys, value types and enum members at every level, unlike the
OpenTelemetry reader: a value the published schema refuses stops the read rather than
reading as a default, and `reject_unknown_keys` and `_wrong` carry the reason. Messages
and parts reach the shared OpenTelemetry helpers only after they are checked here, so
that dialect stays tolerant. This is also the only dialect that can *declare* what it
records, which is why converting an OTel export into it is how an operator adds the
authorization dimensions their framework does not emit.
"""

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any, TypeVar

from guardana.core.trace._parse import (
    TraceLoadError,
    message_from,
    parts_from,
    reject_unknown_keys,
    text_of,
)
from guardana.core.trace.agent import AgentRef
from guardana.core.trace.authorization import (
    Approval,
    ApprovalOutcome,
    ApproverKind,
    Consent,
    PolicyDecision,
    PolicyOutcome,
)
from guardana.core.trace.content import ContentPart
from guardana.core.trace.effect import EffectStatus, SideEffect, SinkKind
from guardana.core.trace.handoff import Handoff
from guardana.core.trace.identity import (
    CredentialKind,
    CredentialRef,
    Delegation,
    Identity,
    SessionRef,
)
from guardana.core.trace.memory import MemoryAction, MemoryOperation
from guardana.core.trace.message import Message
from guardana.core.trace.model import TRACE_SCHEMA_VERSION, Dimension, TraceTruncation
from guardana.core.trace.retrieval import Retrieval, RetrievedDocument
from guardana.core.trace.span import ModelCall, Span, SpanKind
from guardana.core.trace.tool import ToolDeclaration, ToolExecution, ToolStatus

VERSION_KEY = "guardana_trace"
"""The key that makes a native trace identifiable and versioned in one field."""

_E = TypeVar("_E", bound=StrEnum)

FOOTER_KEY = "guardana_trace_end"
"""The key that makes the last record a sign-off rather than a span.

A file being appended to by a live agent cannot go back and amend its header, so
"this session ended" has to arrive at the end. It is opt-in from the header, because
reading every footerless file as truncated would turn every trace written before this
existed into a decline.
"""

_HEADER_KEYS = frozenset(
    {VERSION_KEY, "trace_id", "producer", "instrumented", "truncated", "attributes", "terminated"}
)
_FOOTER_KEYS = frozenset({FOOTER_KEY, "spans"})
_SPAN_KEYS = frozenset(
    {
        "span_id",
        "kind",
        "name",
        "agent",
        "parent_span_id",
        "started_at",
        "ended_at",
        "error",
        "model",
        "messages",
        "system_instructions",
        "tool_offers",
        "tool",
        "retrieval",
        "memory",
        "handoff",
        "conversation_id",
        "identity",
        "delegations",
        "consents",
        "policy_decisions",
        "approvals",
        "effects",
    }
)
OBJECT_KEYS: Mapping[str, frozenset[str]] = {
    "header": _HEADER_KEYS,
    "header.producer": frozenset({"name", "version", "recorded_at"}),
    "footer": _FOOTER_KEYS,
    "span": _SPAN_KEYS,
    "span.agent": frozenset({"name", "id"}),
    "span.model": frozenset(
        {
            "provider",
            "request_model",
            "response_model",
            "input_tokens",
            "output_tokens",
            "finish_reasons",
        }
    ),
    "span.tool_offers[]": frozenset({"name", "description", "schema", "tool_type"}),
    "span.tool": frozenset(
        {"name", "call_id", "arguments", "result", "status", "mutates", "server"}
    ),
    "span.retrieval": frozenset({"query", "source", "tenant", "documents"}),
    "span.retrieval.documents[]": frozenset(
        {"id", "content", "source", "tenant", "score", "metadata"}
    ),
    "span.memory": frozenset({"action", "store", "key", "content", "origin_span_id"}),
    "span.handoff": frozenset({"from_agent", "to_agent", "payload", "carried_scopes"}),
    "span.identity": frozenset({"actor", "credential", "claimed_resource", "session"}),
    "span.delegations[]": frozenset({"actor", "boundary", "on_behalf_of", "credential", "scopes"}),
    "span.consents[]": frozenset({"client", "granted", "scopes", "subject", "recorded_at"}),
    "span.policy_decisions[]": frozenset({"outcome", "action", "policy", "rationale"}),
    "span.approvals[]": frozenset(
        {"action", "outcome", "approver", "approver_kind", "requested_at", "decided_at"}
    ),
    "span.effects[]": frozenset({"sink", "action", "target", "status", "reversible", "detail"}),
    "session": frozenset({"id", "protocol"}),
    "credential": frozenset({"kind", "digest", "value", "audience", "issuer", "subject", "scopes"}),
    "message": frozenset({"role", "parts", "finish_reason"}),
    "part": frozenset(
        {
            "type",
            "content",
            "id",
            "name",
            "arguments",
            "response",
            "media_type",
            "mime_type",
            "uri",
            "url",
            "digest",
            "size_bytes",
            "data",
        }
    ),
}
"""The keys each object of this dialect allows, by its place in the published schema.

One table rather than a set beside each parser, so a test can hold it equal to
`schemas/trace-v3.schema.json` and the reader cannot accept what the schema refuses.
"""


class NativeHeader:
    """What the first line of a native trace declares about the whole file."""

    def __init__(self, raw: Mapping[str, Any]) -> None:
        """Read and validate the header, refusing a version this build cannot read."""
        reject_unknown_keys(raw, _HEADER_KEYS, "trace header")
        self.version = version_of(raw)
        self.trace_id = text_of(raw, "trace_id", "trace header")
        producer = _object(raw, "producer", _HEADER) or {}
        at = f"{_HEADER}.producer"
        _closed(producer, "header.producer", at)
        self.producer = _text(producer, "name", at) or "unknown"
        self.producer_version = _text(producer, "version", at)
        self.recorded_at = _time(producer, "recorded_at", at)
        self.instrumented = _dimensions(raw)
        self.truncated = _member(raw, "truncated", TraceTruncation, _HEADER)
        self.attributes = _map(raw, "attributes", _HEADER)
        self.terminated = _bool(raw, "terminated", _HEADER) is True
        """Whether this producer promised a footer, so its absence means truncation."""


class NativeFooter:
    """The last record of a file whose header promised one.

    It carries a count rather than only a full stop. A footer saying nothing but "I
    finished" would certify a file whose middle a log shipper had eaten — a fresh
    false green produced by the mechanism installed to remove one.
    """

    def __init__(self, raw: Mapping[str, Any], declared_version: int) -> None:
        """Read the footer, refusing one that does not describe this file."""
        reject_unknown_keys(raw, _FOOTER_KEYS, "trace footer")
        declared = raw.get(FOOTER_KEY)
        if declared != declared_version:
            raise TraceLoadError(
                f"the trace footer declares {FOOTER_KEY} {declared!r} while the header declares "
                f"schema version {declared_version} — one file cannot be two versions"
            )
        spans = raw.get("spans")
        if isinstance(spans, bool) or not isinstance(spans, int) or spans < 0:
            raise TraceLoadError(
                f"the trace footer must carry 'spans' as the number of span records the "
                f"producer wrote, and carries {spans!r} — without it the footer is a full "
                f"stop rather than a claim that nothing went missing"
            )
        self.spans = spans


def version_of(raw: Mapping[str, Any]) -> int:
    """Read the schema version, refusing both an absent one and one from the future.

    A missing version is an error rather than a default of 1: guessing is how an
    unversioned format acquires a version in name only. A *newer* version is refused
    because reading it as this one would drop the fields this build does not know and
    grade what was left — a partial trace reported as a whole one.
    """
    version = raw.get(VERSION_KEY)
    if isinstance(version, bool) or not isinstance(version, int):
        raise TraceLoadError(
            f"a native trace must open with a header carrying {VERSION_KEY!r} as an integer "
            f"(pass --dialect otel for an OpenTelemetry export)"
        )
    if version > TRACE_SCHEMA_VERSION:
        raise TraceLoadError(
            f"this trace is schema version {version} and this build reads up to "
            f"{TRACE_SCHEMA_VERSION} — reading it anyway would drop the fields this build "
            f"does not know and grade what was left. Upgrade Guardana."
        )
    if version < 1:
        raise TraceLoadError(f"{VERSION_KEY} must be 1 or greater, got {version}")
    return version


def migrate_header(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """Carry a header forward to the current schema, inventing nothing.

    Returns the migrated mapping, and the caller parses *that* — the v1 version of
    this took the already-parsed header's version and threw its own result away, so
    a migration that needed to change a field could not have. A seam whose output
    nothing consumes is a seam nobody would notice was broken.

    Two steps so far, and neither touches the header: v2 added a per-span field and v3
    added a per-approval one, so a header carries forward unchanged apart from the
    version it now declares. The spans need no step because an added field is absent in
    the older file and absent is what it means — except `approver`, where the older
    spelling carries a meaning, and `_approver` reads it in both files rather than
    rewriting one into the other.
    """
    version = version_of(raw)
    migrated = dict(raw)
    for step in range(version, TRACE_SCHEMA_VERSION):
        migrate = _MIGRATIONS.get(step)
        if migrate is None:
            raise TraceLoadError(f"no migration path from trace schema version {step}")
        migrated = migrate(migrated)
        migrated[VERSION_KEY] = step + 1
    return migrated


def _migrate_1_to_2(raw: dict[str, Any]) -> dict[str, Any]:
    """v2 added `Span.agent`. The header is unchanged; every span gains an absent field."""
    return raw


def _migrate_2_to_3(raw: dict[str, Any]) -> dict[str, Any]:
    """v3 added `Approval.approver_kind`, which is per-approval. The header is unchanged."""
    return raw


_MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {
    1: _migrate_1_to_2,
    2: _migrate_2_to_3,
}


def _dimensions(raw: Mapping[str, Any]) -> frozenset[Dimension]:
    """Read the declared dimensions, refusing a name this build does not know.

    Refused rather than ignored: a producer that declares `aprovals` believes it is
    recording approvals, and silently reading that as "does not record approvals"
    would turn their typo into missing coverage nobody is told about.
    """
    declared = _strings(raw, "instrumented", _HEADER) or ()
    known = {str(d): d for d in Dimension}
    unknown = sorted(set(declared) - set(known))
    if unknown:
        raise TraceLoadError(
            f"trace header.instrumented names unknown dimension(s) {', '.join(unknown)}; "
            f"known dimensions are {', '.join(sorted(known))}"
        )
    return frozenset(known[name] for name in declared)


def span_from(raw: Mapping[str, Any]) -> Span:
    """Read one native span record, refusing an unknown key or a value the schema refuses."""
    reject_unknown_keys(raw, _SPAN_KEYS, "span")
    span_id = text_of(raw, "span_id", "span")
    try:
        return _span(raw, span_id)
    except TraceLoadError as exc:
        raise TraceLoadError(f"span {span_id!r}: {exc}") from exc


def _span(raw: Mapping[str, Any], span_id: str) -> Span:
    return Span(
        span_id=span_id,
        kind=_member(raw, "kind", SpanKind, "") or SpanKind.OTHER,
        name=_text(raw, "name", "") or span_id,
        agent=_agent(raw),
        parent_span_id=_text(raw, "parent_span_id", ""),
        started_at=_time(raw, "started_at", ""),
        ended_at=_time(raw, "ended_at", ""),
        error=_text(raw, "error", ""),
        model=_model(raw),
        messages=tuple(_message(m, at) for at, m in _items(raw, "messages", "")),
        system_instructions=_parts(raw, "system_instructions", ""),
        tool_offers=tuple(_offer(o, at) for at, o in _items(raw, "tool_offers", "")),
        tool=_tool(raw),
        retrieval=_retrieval(raw),
        memory=_memory(raw),
        handoff=_handoff(raw),
        conversation_id=_text(raw, "conversation_id", ""),
        identity=_identity(raw),
        delegations=tuple(_delegation(d, at) for at, d in _items(raw, "delegations", "")),
        consents=tuple(_consent(c, at) for at, c in _items(raw, "consents", "")),
        policy_decisions=tuple(_policy(p, at) for at, p in _items(raw, "policy_decisions", "")),
        approvals=tuple(_approval(a, at) for at, a in _items(raw, "approvals", "")),
        effects=tuple(_effect(e, at) for at, e in _items(raw, "effects", "")),
    )


_HEADER = "trace header"


def _closed(raw: Mapping[str, Any], location: str, what: str) -> None:
    """Refuse a key the schema object at `location` does not define."""
    reject_unknown_keys(raw, OBJECT_KEYS[location], what)


def _at(at: str, key: str | int) -> str:
    """Name a field by its path from the span or header, as an error message spells it."""
    if isinstance(key, int):
        return f"{at}[{key}]"
    return f"{at}.{key}" if at else key


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int | float):
        return "a number"
    if isinstance(value, str):
        return "a string"
    return "an array" if isinstance(value, list) else "an object"


def _wrong(at: str, key: str, expected: str, value: object) -> TraceLoadError:
    """Refuse a value of a type the schema does not give the field.

    Read as absent, `"reversible": "false"` would say nobody recorded whether the effect
    could be undone, and `"terminated": "true"` would withdraw the producer's promise
    of a footer: each a cleaner record than the one the producer wrote.
    """
    return TraceLoadError(
        f"{_at(at, key)} must be {expected}, not {_json_type(value)} — the schema gives it "
        f"no other type, and reading it as absent would grade a record nobody wrote"
    )


def _text(raw: Mapping[str, Any], key: str, at: str) -> str | None:
    """Read a string field; absent or empty reads as None, any other type is refused."""
    if key not in raw:
        return None
    value = raw[key]
    if not isinstance(value, str):
        raise _wrong(at, key, "a JSON string", value)
    return value or None


def _bool(raw: Mapping[str, Any], key: str, at: str) -> bool | None:
    """Read a tri-state boolean: True, False, or None when the key is absent."""
    if key not in raw:
        return None
    value = raw[key]
    if not isinstance(value, bool):
        raise _wrong(at, key, "a JSON boolean", value)
    return value


def _integer(raw: Mapping[str, Any], key: str, at: str) -> int | None:
    """Read an integer field; a boolean or a fraction is refused."""
    if key not in raw:
        return None
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _wrong(at, key, "a JSON integer", value)
    return value


def _number(raw: Mapping[str, Any], key: str, at: str) -> float | None:
    """Read a number field; a boolean is refused."""
    if key not in raw:
        return None
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _wrong(at, key, "a JSON number", value)
    return float(value)


def _time(raw: Mapping[str, Any], key: str, at: str) -> datetime | None:
    """Read a timestamp string; one that does not parse reads as absent, never as now.

    The schema types it as a string and no more, so a string in another format is the
    producer's clock written in a form this build cannot place, which is not a fact to
    substitute for.
    """
    value = _text(raw, key, at)
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _member(raw: Mapping[str, Any], key: str, enum: type[_E], at: str) -> _E | None:
    """Read an enum member, None when absent; refuse any value the schema does not list.

    A value outside the list is never read as `other` or `unknown`: a misspelt `Shell`
    read as `other` reaches no rule that forbids a shell. `other` and `unknown` are what
    a producer writes when it means them.
    """
    if key not in raw:
        return None
    value = raw[key]
    known = {str(member): member for member in enum}
    if isinstance(value, str) and value in known:
        return known[value]
    raise TraceLoadError(
        f"{_at(at, key)} is {json.dumps(value)}, which is not one of {', '.join(known)}"
    )


def _required_member(raw: Mapping[str, Any], key: str, enum: type[_E], at: str) -> _E:
    """Read an enum member the schema requires, refusing its absence rather than defaulting."""
    member = _member(raw, key, enum, at)
    if member is None:
        raise TraceLoadError(
            f"{_at(at, key)} is required, one of {', '.join(str(m) for m in enum)}"
        )
    return member


def _required_text(raw: Mapping[str, Any], key: str, at: str) -> str:
    """Read a string the schema requires, refusing its absence rather than naming it `unknown`.

    A rule compares these values, so a stand-in matches nothing and the record would be
    graded as though it did not concern the action or boundary it was written about.
    """
    value = _text(raw, key, at)
    if value is None:
        raise TraceLoadError(f"{_at(at, key)} is required, a string")
    return value


def _object(raw: Mapping[str, Any], key: str, at: str) -> dict[str, Any] | None:
    """Read an object the schema defines, None when absent; refuse any other value.

    The shared parsers read a string or a number in its place as an empty record or as
    text, which is a record the producer never wrote.
    """
    if key not in raw:
        return None
    value = raw[key]
    if not isinstance(value, dict):
        raise _wrong(at, key, "a JSON object", value)
    return value


def _items(raw: Mapping[str, Any], key: str, at: str) -> list[tuple[str, dict[str, Any]]]:
    """Read a list of objects with the path of each, empty when absent; refuse anything else."""
    if key not in raw:
        return []
    value = raw[key]
    if not isinstance(value, list):
        raise _wrong(at, key, "a JSON array", value)
    where = _at(at, key)
    items: list[tuple[str, dict[str, Any]]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise TraceLoadError(
                f"{_at(where, index)} must be a JSON object, not {_json_type(item)}"
            )
        items.append((_at(where, index), item))
    return items


def _strings(raw: Mapping[str, Any], key: str, at: str) -> tuple[str, ...] | None:
    """Read a list of strings the schema defines, None when absent; refuse anything else.

    Absence and an empty list stay different facts, which a scope list needs.
    """
    if key not in raw:
        return None
    value = raw[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _wrong(at, key, "a JSON array of strings", value)
    return tuple(value)


def _map(raw: Mapping[str, Any], key: str, at: str) -> dict[str, str]:
    """Read a string map the schema defines, empty when absent; refuse a value that is not one."""
    value = _object(raw, key, at) or {}
    where = _at(at, key)
    for name, item in value.items():
        if not isinstance(item, str):
            raise _wrong(where, name, "a JSON string", item)
    return dict(value)


_PART_STRINGS = ("id", "name", "media_type", "mime_type", "uri", "url", "digest", "data")


def _parts(raw: Mapping[str, Any], key: str, at: str) -> tuple[ContentPart, ...]:
    """Check every part's keys and value types here, then read them with the shared OTel parser.

    The shared parser reads only the keys it knows and reads a value of another type as
    absent, which is right for OpenTelemetry and the fail-open here: a part written
    `{"type": "text", "text": ...}` would carry no text and grade as an empty message.
    """
    parts = _items(raw, key, at)
    for where, part in parts:
        _closed(part, "part", f"the part at {where}")
        if not isinstance(part.get("type"), str):
            raise TraceLoadError(f"the part at {where} must name its `type` as a string")
        for name in _PART_STRINGS:
            _text(part, name, where)
        _integer(part, "size_bytes", where)
    return parts_from([part for _, part in parts])


def _message(raw: dict[str, Any], at: str) -> Message:
    """Check a message's keys and value types and its parts', then read it with the OTel parser.

    Only `parts` is a native message's list: the shared parser's fallback to
    `content` serves OpenTelemetry producers and would let a native typo through.
    """
    _closed(raw, "message", f"the message at {at}")
    _text(raw, "role", at)
    _text(raw, "finish_reason", at)
    _parts(raw, "parts", at)
    return message_from(raw)


def _model(span: Mapping[str, Any]) -> ModelCall | None:
    raw = _object(span, "model", "")
    if raw is None:
        return None
    _closed(raw, "span.model", "model")
    return ModelCall(
        provider=_text(raw, "provider", "model"),
        request_model=_text(raw, "request_model", "model"),
        response_model=_text(raw, "response_model", "model"),
        input_tokens=_integer(raw, "input_tokens", "model"),
        output_tokens=_integer(raw, "output_tokens", "model"),
        finish_reasons=_strings(raw, "finish_reasons", "model") or (),
    )


def _offer(raw: dict[str, Any], at: str) -> ToolDeclaration:
    _closed(raw, "span.tool_offers[]", at)
    return ToolDeclaration(
        name=_text(raw, "name", at) or "unknown",
        description=_text(raw, "description", at),
        schema=_text(raw, "schema", at),
        tool_type=_text(raw, "tool_type", at),
    )


def _tool(span: Mapping[str, Any]) -> ToolExecution | None:
    raw = _object(span, "tool", "")
    if raw is None:
        return None
    _closed(raw, "span.tool", "tool")
    return ToolExecution(
        name=_text(raw, "name", "tool") or "unknown",
        call_id=_text(raw, "call_id", "tool"),
        arguments=_text(raw, "arguments", "tool"),
        result=_parts(raw, "result", "tool"),
        status=_member(raw, "status", ToolStatus, "tool") or ToolStatus.UNKNOWN,
        mutates=_bool(raw, "mutates", "tool"),
        server=_text(raw, "server", "tool"),
    )


def _retrieval(span: Mapping[str, Any]) -> Retrieval | None:
    raw = _object(span, "retrieval", "")
    if raw is None:
        return None
    _closed(raw, "span.retrieval", "retrieval")
    return Retrieval(
        query=_text(raw, "query", "retrieval"),
        source=_text(raw, "source", "retrieval"),
        tenant=_text(raw, "tenant", "retrieval"),
        documents=tuple(_document(d, at) for at, d in _items(raw, "documents", "retrieval")),
    )


def _document(raw: dict[str, Any], at: str) -> RetrievedDocument:
    _closed(raw, "span.retrieval.documents[]", at)
    return RetrievedDocument(
        id=_text(raw, "id", at) or "unknown",
        content=_parts(raw, "content", at),
        source=_text(raw, "source", at),
        tenant=_text(raw, "tenant", at),
        score=_number(raw, "score", at),
        metadata=_map(raw, "metadata", at),
    )


def _memory(span: Mapping[str, Any]) -> MemoryOperation | None:
    raw = _object(span, "memory", "")
    if raw is None:
        return None
    _closed(raw, "span.memory", "memory")
    return MemoryOperation(
        action=_member(raw, "action", MemoryAction, "memory") or MemoryAction.READ,
        store=_text(raw, "store", "memory"),
        key=_text(raw, "key", "memory"),
        content=_parts(raw, "content", "memory"),
        origin_span_id=_text(raw, "origin_span_id", "memory"),
    )


def _agent(span: Mapping[str, Any]) -> AgentRef | None:
    """Read which agent performed this step, refusing a record with no name in it.

    A nameless actor is dropped rather than recorded as `"unknown"`: the point of the
    field is to tell two agents apart, and a trace whose every span is performed by
    `unknown` would let a rule compare two different agents and find them equal.
    """
    block = _object(span, "agent", "")
    if block is None:
        return None
    _closed(block, "span.agent", "agent")
    name = _text(block, "name", "agent")
    identifier = _text(block, "id", "agent")
    if name is None:
        return None
    return AgentRef(name=name, id=identifier)


def _handoff(span: Mapping[str, Any]) -> Handoff | None:
    raw = _object(span, "handoff", "")
    if raw is None:
        return None
    _closed(raw, "span.handoff", "handoff")
    return Handoff(
        from_agent=_text(raw, "from_agent", "handoff") or "unknown",
        to_agent=_text(raw, "to_agent", "handoff") or "unknown",
        payload=_parts(raw, "payload", "handoff"),
        carried_scopes=_strings(raw, "carried_scopes", "handoff"),
    )


def _credential(holder: Mapping[str, Any], at: str) -> CredentialRef | None:
    """Read a credential reference, digesting a value the trace recorded in the clear.

    A trace that carries the raw token gets it hashed here and nowhere kept, because
    `CredentialRef` has no field to put it in. That is the seam: a producer's
    carelessness stops at the reader rather than travelling into a report.
    """
    block = _object(holder, "credential", at)
    if block is None:
        return None
    where = _at(at, "credential")
    _closed(block, "credential", where)
    digest = _text(block, "digest", where)
    value = _text(block, "value", where)
    kind = _member(block, "kind", CredentialKind, where) or CredentialKind.OTHER
    if digest is None and value is not None:
        digest = CredentialRef.of_value(value, kind).digest
    return CredentialRef(
        kind=kind,
        digest=digest,
        audience=_strings(block, "audience", where) or (),
        issuer=_text(block, "issuer", where),
        subject=_text(block, "subject", where),
        scopes=_strings(block, "scopes", where),
    )


def _identity(span: Mapping[str, Any]) -> Identity | None:
    raw = _object(span, "identity", "")
    if raw is None:
        return None
    _closed(raw, "span.identity", "identity")
    return Identity(
        actor=_text(raw, "actor", "identity"),
        credential=_credential(raw, "identity"),
        claimed_resource=_text(raw, "claimed_resource", "identity"),
        session=_session(raw, "identity"),
    )


def _session(identity: Mapping[str, Any], at: str) -> SessionRef | None:
    if "session" not in identity:
        return None
    raw = identity["session"]
    if isinstance(raw, str):
        return SessionRef(id=raw)
    if not isinstance(raw, dict):
        raise _wrong(at, "session", "a session id string or a JSON object", raw)
    where = _at(at, "session")
    _closed(raw, "session", where)
    identifier = _text(raw, "id", where)
    protocol = _text(raw, "protocol", where)
    return SessionRef(id=identifier, protocol=protocol) if identifier is not None else None


def _delegation(raw: dict[str, Any], at: str) -> Delegation:
    _closed(raw, "span.delegations[]", at)
    return Delegation(
        actor=_required_text(raw, "actor", at),
        boundary=_required_text(raw, "boundary", at),
        on_behalf_of=_text(raw, "on_behalf_of", at),
        credential=_credential(raw, at),
        scopes=_strings(raw, "scopes", at),
    )


def _consent(raw: dict[str, Any], at: str) -> Consent:
    _closed(raw, "span.consents[]", at)
    granted = _bool(raw, "granted", at)
    return Consent(
        client=_required_text(raw, "client", at),
        granted=granted if granted is not None else False,
        scopes=_strings(raw, "scopes", at),
        subject=_text(raw, "subject", at),
        recorded_at=_time(raw, "recorded_at", at),
    )


def _policy(raw: dict[str, Any], at: str) -> PolicyDecision:
    _closed(raw, "span.policy_decisions[]", at)
    return PolicyDecision(
        outcome=_required_member(raw, "outcome", PolicyOutcome, at),
        action=_required_text(raw, "action", at),
        policy=_text(raw, "policy", at),
        rationale=_text(raw, "rationale", at),
    )


_APPROVER_KINDS = {str(kind): kind for kind in ApproverKind}


def _approver(raw: Mapping[str, Any], at: str) -> tuple[str | None, ApproverKind | None]:
    """Read who granted an approval, and whether they are a person.

    A kind outside the list is refused, as every enum here is: there is no honest
    default for "is this human oversight", and a misspelled `persson` read as an
    unrecorded kind would quietly turn a contract demanding a human into one satisfied
    by the agent's own gate.

    An older file spells the kind into the name — `human:alice`, the convention
    `docs/usage-contracts.md` has documented since contracts shipped — so that prefix
    is read as the structure it always stood for. An explicit `approver_kind` wins,
    and a name whose prefix names nothing known is just a name.
    """
    approver = _text(raw, "approver", at)
    declared = _member(raw, "approver_kind", ApproverKind, at)
    if declared is not None:
        if approver is None:
            raise TraceLoadError(
                f"{at} records approver_kind {str(declared)!r} and no approver — a claim "
                f"that somebody approved, minus the somebody"
            )
        return approver, declared
    if approver is None:
        return None, None
    prefix, separator, name = approver.partition(":")
    if separator and name and prefix in _APPROVER_KINDS:
        return name, _APPROVER_KINDS[prefix]
    return approver, None


def _approval(raw: dict[str, Any], at: str) -> Approval:
    _closed(raw, "span.approvals[]", at)
    approver, approver_kind = _approver(raw, at)
    return Approval(
        action=_required_text(raw, "action", at),
        outcome=_required_member(raw, "outcome", ApprovalOutcome, at),
        approver=approver,
        approver_kind=approver_kind,
        requested_at=_time(raw, "requested_at", at),
        decided_at=_time(raw, "decided_at", at),
    )


def _effect(raw: dict[str, Any], at: str) -> SideEffect:
    _closed(raw, "span.effects[]", at)
    return SideEffect(
        sink=_required_member(raw, "sink", SinkKind, at),
        action=_required_text(raw, "action", at),
        target=_text(raw, "target", at),
        status=_member(raw, "status", EffectStatus, at) or EffectStatus.ATTEMPTED,
        reversible=_bool(raw, "reversible", at),
        detail=_text(raw, "detail", at),
    )


def parts_of(raw: object) -> tuple[ContentPart, ...]:
    """Read content parts — re-exported so the serializer and reader share one shape."""
    return parts_from(raw)
