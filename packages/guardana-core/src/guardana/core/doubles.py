"""Stateful tool doubles an application runs with in CI, over the records a fixtures file declares.

`open_doubles` serves the `tools:` of a `guardana-fixtures.yaml` from an in-memory copy of
its `records:`, each record carrying its presence marker, and writes every call into a
native trace. The doubles behave as a backend that enforces tenancy, the way row-level
security does: a call names the tenant the application resolved (`acting_as`) and sees
only that tenant's records. A tenant leak therefore needs the application to name the
wrong tenant, which the tenancy rules detect from the replies; the trace is evidence of
what the application did with its tools, never the tenant verdict, because the tenant in
it is the application's own claim.
"""

import atexit
import json
import os
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import Any

from guardana.core import __version__
from guardana.core.fixtures import (
    RECORD_MARKER_FIELD,
    FieldValue,
    Fixtures,
    Tool,
    ToolOp,
    load_fixtures,
)
from guardana.core.trace import (
    Dimension,
    EffectStatus,
    SideEffect,
    SinkKind,
    SinkMap,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    TraceWriteError,
    TraceWriter,
    create_trace,
)

PRODUCER = "guardana.doubles"
"""The producer name the doubles' trace header carries."""

INSTRUMENTED = (Dimension.TOOLS, Dimension.EFFECTS)
"""What the doubles' trace declares: tool calls and their effects, never retrieval or identity.

Every record a double returns belongs to the tenant the application named, so a retrieval
rule over it would run and could never fire.
"""

_ID = "id"
_QUERY = "query"


class DoublesError(RuntimeError):
    """A call or a setup the doubles refuse, named down to what is missing."""


@dataclass(slots=True)
class _Row:
    """One record as the doubles hold it: its owner, its fields and, when seeded, its term."""

    id: str
    owner: str
    fields: dict[str, FieldValue]
    term: str | None = None

    def data(self) -> dict[str, FieldValue]:
        """Return the record as a call hands it back: a copy, so the caller cannot edit state."""
        return {**self.fields, _ID: self.id}

    def matches(self, query: str) -> bool:
        """Whether the query, case-folded, is in the retrieval term or in any field value."""
        wanted = query.casefold()
        values = [str(value) for value in self.fields.values()]
        if self.term is not None:
            values.append(self.term)
        return any(wanted in value.casefold() for value in values)


@dataclass(frozen=True, slots=True)
class _Outcome:
    """What a call returns, and what its span records."""

    data: Any
    done: bool
    target: str | None = None
    error: str | None = None
    commit: Callable[[], None] = field(default=lambda: None)


class Doubles:
    """The declared tools, served over an in-memory copy of the declared records.

    Built by `open_doubles`. Thread-safe: one lock covers a call's state change and its
    span, so the trace lists calls in the order they changed state. State lives as long
    as the process and is never reset between cases.
    """

    def __init__(self, fixtures: Fixtures, writer: TraceWriter) -> None:
        """Copy the records and hold the trace; `open_doubles` is the way to build one."""
        self._fixtures = fixtures
        self._writer = writer
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._tenant: ContextVar[str | None] = ContextVar(
            f"guardana.doubles.tenant.{id(self)}", default=None
        )
        self._tools = {tool.name: tool for tool in fixtures.tools}
        self._rows: dict[str, dict[str, _Row]] = {name: {} for name in fixtures.collections}
        for item in fixtures.records:
            self._rows[str(item.collection)][item.id] = _Row(
                id=item.id, owner=item.owner, fields=item.served_fields(), term=item.markers.term
            )
        self._calls = 0
        self._closed = False
        self._broken = False
        atexit.register(self._at_exit)

    @property
    def fixtures(self) -> Fixtures:
        """The fixtures file the doubles serve."""
        return self._fixtures

    @property
    def tools(self) -> tuple[Tool, ...]:
        """The tools the doubles serve, in the order the file declares them."""
        return self._fixtures.tools

    @contextmanager
    def acting_as(self, tenant: str) -> Iterator[None]:
        """Make `tenant` the one every call in this context acts for.

        Held in a context variable, so concurrent requests do not share it. A context
        variable does not follow work into a thread pool: submit the work through
        `contextvars.copy_context().run`, or enter `acting_as` inside the worker.
        """
        self._refuse_undeclared(tenant)
        token = self._tenant.set(tenant)
        try:
            yield
        finally:
            self._tenant.reset(token)

    def tool(self, name: str) -> Callable[..., Any]:
        """Return the declared tool `name` as a callable taking keyword arguments."""
        self._declared_tool(name)
        return partial(self.call, name)

    def call(self, name: str, /, **arguments: object) -> Any:  # noqa: ANN401 — JSON data, shaped by the tool
        """Call the declared tool `name` as the acting tenant, and return JSON-able data.

        Raises `DoublesError`, before anything is written, for a forked process, closed
        doubles, an undeclared tool, no acting tenant and arguments the tool does not take.
        A record the acting tenant does not own is invisible, as under row-level
        security: `get`, `update` and `delete` return `None` for it, as for an id that
        does not exist.
        """
        self._refuse_fork()
        tool = self._declared_tool(name)
        tenant = self._tenant.get()
        if tenant is None:
            raise DoublesError(
                f"tool {name!r} was called with no acting tenant; wrap the request in "
                f"`with doubles.acting_as(tenant):`, so every call says whose data it reaches"
            )
        self._refuse_undeclared(tenant)
        _refuse_arguments(tool, arguments)
        with self._lock:
            if self._closed:
                raise DoublesError("these doubles are closed; nothing is written after the footer")
            if self._broken:
                raise DoublesError(
                    "an earlier call could not be written to the trace, so the trace is no longer "
                    "a complete record; these doubles take no further call"
                )
            started = datetime.now(UTC)
            outcome = self._perform(tool, tenant, arguments)
            self._calls += 1
            span = _span(f"call-{self._calls}", tool, arguments, outcome, started)
            try:
                self._writer.span(span)
            except TraceWriteError as exc:
                self._broken = True
                raise DoublesError(f"the call to {name!r} could not be traced: {exc}") from exc
            outcome.commit()
        return outcome.data

    def close(self) -> None:
        """Write the footer and release the trace; a second close does nothing.

        No footer follows a call that could not be written, so a lost span reads as a
        truncated trace. Doubles that were never called leave the file empty.
        """
        self._refuse_fork()
        self._close()
        atexit.unregister(self._at_exit)

    def __enter__(self) -> "Doubles":
        """Hand back the open doubles, so leaving the block closes them."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close, footer included, whether or not the application raised.

        Every call that returned is already in the trace, so the record of the calls is
        complete even when the application is not.
        """
        self.close()

    def _close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._broken:
                self._writer.close()
            else:
                self._writer.finish()

    def _at_exit(self) -> None:
        """Close at interpreter exit, unless this is a forked child, which writes nothing."""
        if os.getpid() == self._pid:
            self._close()

    def _refuse_fork(self) -> None:
        if os.getpid() != self._pid:
            raise DoublesError(
                f"these doubles were opened by process {self._pid} and this is process "
                f"{os.getpid()}; a forked process shares the trace file and its spans would "
                f"interleave with the parent's. Open the doubles after forking, in each process "
                f"with a trace of its own"
            )

    def _declared_tool(self, name: str) -> Tool:
        tool = self._tools.get(name)
        if tool is None:
            raise DoublesError(
                f"tool {name!r} is not declared under `tools:` in {self._fixtures.path} "
                f"({', '.join(self._tools) or 'none'})"
            )
        return tool

    def _refuse_undeclared(self, tenant: str) -> None:
        if tenant not in self._fixtures.tenant_names:
            raise DoublesError(
                f"tenant {tenant!r} is not declared under `tenants:` in {self._fixtures.path} "
                f"({', '.join(self._fixtures.tenant_names)})"
            )

    def _perform(self, tool: Tool, tenant: str, arguments: Mapping[str, object]) -> _Outcome:
        """Work out what a call does without doing it; `commit` applies the change."""
        if tool.op is ToolOp.SEND:
            return _Outcome(data={"sent": True}, done=True)
        rows = self._rows[str(tool.collection)]
        if tool.op is ToolOp.SEARCH:
            query = str(arguments[_QUERY])
            found = [r.data() for r in rows.values() if r.owner == tenant and r.matches(query)]
            return _Outcome(data=found, done=True)
        record_id = str(arguments[_ID])
        target = f"{tool.collection}/{record_id}"
        if tool.op is ToolOp.CREATE:
            return _created(rows, _Row(record_id, tenant, _fields(arguments)), target)
        visible = rows.get(record_id)
        if visible is None or visible.owner != tenant:
            if tool.op is ToolOp.GET:
                return _Outcome(None, True, target)
            return _Outcome(None, False, target, f"no record {target} visible to the acting tenant")
        return _on_visible(tool.op, rows, visible, _fields(arguments), target)


def _fields(arguments: Mapping[str, object]) -> dict[str, FieldValue]:
    """Return the record fields a call names: every argument but `id`, already checked."""
    return {
        key: value
        for key, value in arguments.items()
        if key != _ID and isinstance(value, str | int | float | bool)
    }


def _created(rows: dict[str, _Row], row: _Row, target: str) -> _Outcome:
    """Add `row` unless its id is taken, by any tenant: ids are unique across a collection."""
    if row.id in rows:
        return _Outcome(None, False, target, f"{target} already exists")
    return _Outcome(row.data(), True, target, commit=partial(_put, rows, row))


def _on_visible(
    op: ToolOp,
    rows: dict[str, _Row],
    row: _Row,
    fields: dict[str, FieldValue],
    target: str,
) -> _Outcome:
    """Read, change or remove a record the acting tenant owns."""
    if op is ToolOp.UPDATE:
        changed = {**row.data(), **fields, _ID: row.id}
        return _Outcome(changed, True, target, commit=partial(row.fields.update, fields))
    if op is ToolOp.DELETE:
        return _Outcome(row.data(), True, target, commit=partial(_remove, rows, row.id))
    return _Outcome(row.data(), True, target)


def _put(rows: dict[str, _Row], row: _Row) -> None:
    rows[row.id] = row


def _remove(rows: dict[str, _Row], record_id: str) -> None:
    del rows[record_id]


def _refuse_arguments(tool: Tool, arguments: Mapping[str, object]) -> None:
    """Refuse arguments the tool does not take, before anything is written."""
    where = f"tool {tool.name!r} ({tool.op})"
    if tool.op is ToolOp.SEND:
        try:
            json.dumps(arguments)
        except (TypeError, ValueError) as exc:
            raise DoublesError(f"{where}: its arguments must be JSON data: {exc}") from exc
        return
    wanted = _QUERY if tool.op is ToolOp.SEARCH else _ID
    value = arguments.get(wanted)
    if not isinstance(value, str) or not value:
        raise DoublesError(f"{where} takes `{wanted}`, a non-empty string")
    extra = sorted(set(arguments) - {wanted})
    if tool.op in {ToolOp.GET, ToolOp.SEARCH, ToolOp.DELETE}:
        if extra:
            raise DoublesError(f"{where} takes only `{wanted}`, not {', '.join(extra)}")
        return
    if tool.op is ToolOp.UPDATE and not extra:
        raise DoublesError(f"{where} names no field to change")
    for key in extra:
        if key == RECORD_MARKER_FIELD:
            raise DoublesError(
                f"{where}: `{RECORD_MARKER_FIELD}` holds the record's presence marker, which "
                f"Guardana derives; a call does not write it"
            )
        if not isinstance(arguments[key], str | int | float | bool):
            raise DoublesError(f"{where}: field {key!r} must be a string, a number or true/false")


def _span(
    span_id: str,
    tool: Tool,
    arguments: Mapping[str, object],
    outcome: _Outcome,
    started: datetime,
) -> Span:
    """Record one call: the tool with its arguments and, for a change or a send, its effect.

    A change that found nothing to change is a failed call with a failed effect: the
    backend refused it, which is the opposite of a consequence.
    """
    effects: tuple[SideEffect, ...] = ()
    if tool.op.has_effect:
        effects = (
            SideEffect(
                sink=SinkKind(str(tool.sink)),
                action=tool.name,
                target=outcome.target if tool.op is not ToolOp.SEND else None,
                status=EffectStatus.EXECUTED if outcome.done else EffectStatus.FAILED,
                reversible=tool.reversible,
            ),
        )
    return Span(
        span_id=span_id,
        kind=SpanKind.TOOL_EXECUTION,
        name=tool.name,
        started_at=started,
        ended_at=datetime.now(UTC),
        error=outcome.error,
        tool=ToolExecution(
            name=tool.name,
            call_id=span_id,
            arguments=json.dumps(dict(arguments), sort_keys=True, ensure_ascii=False),
            status=ToolStatus.SUCCEEDED if outcome.done else ToolStatus.FAILED,
            mutates=tool.op.has_effect and outcome.done,
        ),
        effects=effects,
    )


def _sinks(fixtures: Fixtures) -> SinkMap:
    """Map every change or send tool to its declared sink; refuse a sink no rule knows."""
    mapped: dict[str, SinkKind] = {}
    for tool in fixtures.tools:
        if not tool.op.has_effect:
            continue
        try:
            mapped[tool.name] = SinkKind(str(tool.sink))
        except ValueError:
            raise DoublesError(
                f"{fixtures.path}: tools.{tool.name} declares sink {tool.sink!r}, which no rule "
                f"reads; use one of {', '.join(s.value for s in SinkKind)}"
            ) from None
    reads = frozenset(t.name for t in fixtures.tools if not t.op.has_effect)
    return SinkMap(mapped, default=SinkKind.OTHER, read_only=reads)


def open_doubles(fixtures: Path | str, *, trace: Path | str) -> Doubles:
    """Load `fixtures`, create the trace at `trace` and return the doubles for its tools.

    The trace file must not exist: a stale file from an earlier job, or a second process
    given the same path, fails the application at startup. Its header goes down with the
    first call, so doubles that are never called leave an empty file, which
    `guardana analyze-trace` refuses. Raises `FixturesError` for a file that does not load
    and `DoublesError` for one that declares no tool, a sink no rule reads, or a trace
    path that cannot be created.
    """
    loaded = load_fixtures(Path(fixtures))
    if not loaded.tools:
        raise DoublesError(
            f"{loaded.path} declares no `tools:`, so the doubles would serve nothing and their "
            f"trace would stay empty"
        )
    sinks = _sinks(loaded)
    try:
        writer = create_trace(
            Path(trace),
            trace_id=uuid.uuid4().hex,
            producer=PRODUCER,
            producer_version=__version__,
            instrumented=INSTRUMENTED,
            sinks=sinks,
            recorded_at=datetime.now(UTC),
            attributes={"fixtures": loaded.name, "fixtures_digest": loaded.digest},
        )
    except TraceWriteError as exc:
        raise DoublesError(str(exc)) from exc
    return Doubles(loaded, writer)


__all__ = ["INSTRUMENTED", "PRODUCER", "Doubles", "DoublesError", "open_doubles"]
