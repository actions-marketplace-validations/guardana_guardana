"""Every way Guardana reaches a model, held to one table of what it carries.

`REQUIREMENTS` is the table `docs/providers.md` prints; a test below holds the page to
it. Each cell is proven against a local HTTP double (`FakeProvider`) or, for
LangChain, a chat-model double — never against a mock of urllib. A cell that says a
thing is not carried names the refusal that keeps the gap from reading as a pass, and
that refusal is tested beside it.
"""

import json
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.error import HTTPError

import pytest
from guardana.adapters.langchain import langchain_target
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target import Capability, EndpointTarget
from guardana.core.target._providers import OllamaTransport, TgiTransport
from guardana.core.target.adapter import AdapterConfig, HttpAdapterTransport
from guardana.core.target.endpoint import (
    ChatMessage,
    ChatTransport,
    EndpointError,
    EndpointUnreachable,
    ToolCall,
    ToolSpec,
    UrllibTransport,
)
from guardana.core.testing._fake_provider import (
    FakeProvider,
    Scripted,
    adapter_reply,
    delayed,
    json_reply,
    malformed_reply,
    ollama_reply,
    openai_reply,
    oversized_reply,
    redirect_reply,
    status_reply,
    tgi_reply,
)

_REPO = Path(__file__).resolve().parents[4]

CARRIED = "carried"
NO_TOOLS = "not carried: no `call_tools` capability"
NO_USAGE = "not carried: a token ceiling is refused"
NOT_HTTP = "not applicable"

SystemDelivery = Literal["role", "flattened", "slot", "folded"]


@dataclass(frozen=True, slots=True)
class Row:
    """What one transport promises to carry to the model, and what it retries."""

    key: str
    transport: str
    system_message: SystemDelivery
    tools: str
    token_usage: str
    tool_turns: str
    retried_statuses: tuple[int, ...] | None


_BUILT_IN_RETRIES = (429, 500, 502, 503, 504)
_ADAPTER_RETRIES = (429, 503)

REQUIREMENTS: tuple[Row, ...] = (
    Row("openai", "`openai`", "role", CARRIED, CARRIED, CARRIED, _BUILT_IN_RETRIES),
    Row("ollama", "`ollama`", "role", NO_TOOLS, CARRIED, NO_TOOLS, _BUILT_IN_RETRIES),
    Row("tgi", "`tgi`", "flattened", NO_TOOLS, NO_USAGE, NO_TOOLS, _BUILT_IN_RETRIES),
    Row(
        "adapter-system-slot",
        "adapter with a `{{system}}` slot",
        "slot",
        NO_TOOLS,
        NO_USAGE,
        NO_TOOLS,
        _ADAPTER_RETRIES,
    ),
    Row(
        "adapter-folded",
        "adapter without a `{{system}}` slot",
        "folded",
        NO_TOOLS,
        NO_USAGE,
        NO_TOOLS,
        _ADAPTER_RETRIES,
    ),
    Row(
        "langchain-tools",
        "LangChain, a model that binds tools",
        "role",
        CARRIED,
        CARRIED,
        CARRIED,
        None,
    ),
    Row(
        "langchain-plain",
        "LangChain, a model that cannot bind tools",
        "role",
        NO_TOOLS,
        CARRIED,
        CARRIED,
        None,
    ),
)
"""The requirements every transport is held to, one row per transport."""

_HEADER = (
    "| transport | system message | tools | token usage | tool turns in history "
    "| retried statuses |"
)


def render_table(rows: Sequence[Row]) -> str:
    """Render the requirements as the Markdown table `docs/providers.md` prints."""
    lines = [_HEADER, "|---|---|---|---|---|---|"]
    for row in rows:
        retried = (
            ", ".join(str(status) for status in row.retried_statuses)
            if row.retried_statuses is not None
            else NOT_HTTP
        )
        cells = (
            row.transport,
            row.system_message,
            row.tools,
            row.token_usage,
            row.tool_turns,
            retried,
        )
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


_SYSTEM = "SYSTEM-PROMPT-MARKER"
_USER = "USER-TURN-MARKER"
_HELLO = (ChatMessage(role="user", content=_USER),)
_TOOL = ToolSpec(name="read_file", description="Read a file.")
_HISTORY = (
    ChatMessage(role="user", content=_USER),
    ChatMessage(
        role="assistant",
        content="",
        tool_calls=(ToolCall(name="read_file", arguments="{}", id="call-7"),),
    ),
    ChatMessage(role="tool", content="file body", tool_call_id="call-7"),
)

Tokens = tuple[int, int] | None


class _Harness(Protocol):
    """One transport behind a target, a way to script its replies, and what it sent."""

    row: Row

    def target(
        self, *, system_prompt: str | None = None, budgets: Budgets | None = None
    ) -> EndpointTarget:
        """Build the target the row describes."""

    def answer(self, text: str, tokens: Tokens = None) -> None:
        """Script the next reply as text, with token counts when given."""

    def answer_tool_call(self, name: str, tokens: Tokens = None) -> None:
        """Script the next reply as a call to `name`, with token counts when given."""

    def sent(self) -> list[dict[str, Any]]:
        """Return every request body that reached the model, oldest first."""


@dataclass(frozen=True, slots=True)
class _Wire:
    transport: Callable[[str, float | None], ChatTransport]
    reply: Callable[[str, Tokens], Scripted]
    tool_reply: Callable[[str, Tokens], Scripted] | None
    missing_field: Scripted


def _openai_usage(tokens: Tokens) -> dict[str, int] | None:
    return None if tokens is None else {"prompt_tokens": tokens[0], "completion_tokens": tokens[1]}


def _openai_tool_reply(name: str, tokens: Tokens) -> Scripted:
    call: dict[str, object] = {
        "id": "call-1",
        "type": "function",
        "function": {"name": name, "arguments": "{}"},
    }
    return openai_reply(None, tool_calls=[call], usage=_openai_usage(tokens))


def _ollama(text: str, tokens: Tokens) -> Scripted:
    if tokens is None:
        return ollama_reply(text)
    return ollama_reply(text, prompt_eval_count=tokens[0], eval_count=tokens[1])


def _timed(factory: Callable[..., ChatTransport]) -> Callable[[str, float | None], ChatTransport]:
    def build(url: str, timeout: float | None) -> ChatTransport:
        return factory() if timeout is None else factory(timeout=timeout)

    return build


def _adapter(body: dict[str, object]) -> Callable[[str, float | None], ChatTransport]:
    def build(url: str, timeout: float | None) -> ChatTransport:
        config = AdapterConfig(url=f"{url}/chat", body=body, response_path="data.reply")
        if timeout is None:
            return HttpAdapterTransport(config)
        return HttpAdapterTransport(config, timeout=timeout)

    return build


_WIRES: dict[str, _Wire] = {
    "openai": _Wire(
        _timed(UrllibTransport),
        lambda text, tokens: openai_reply(text, usage=_openai_usage(tokens)),
        _openai_tool_reply,
        json_reply({"choices": [{"message": {"role": "assistant"}}]}),
    ),
    "ollama": _Wire(
        _timed(OllamaTransport),
        _ollama,
        None,
        json_reply({"message": {"role": "assistant"}, "done": True}),
    ),
    "tgi": _Wire(
        _timed(TgiTransport),
        lambda text, tokens: tgi_reply(text),
        None,
        json_reply({"details": {}}),
    ),
    "adapter-system-slot": _Wire(
        _adapter({"system": "{{system}}", "message": "{{prompt}}"}),
        lambda text, tokens: adapter_reply(text),
        None,
        json_reply({"data": {}}),
    ),
    "adapter-folded": _Wire(
        _adapter({"message": "{{prompt}}"}),
        lambda text, tokens: adapter_reply(text),
        None,
        json_reply({"data": {}}),
    ),
}


class _HttpHarness:
    """A built-in or adapter transport talking to a `FakeProvider`."""

    def __init__(self, row: Row, provider: FakeProvider) -> None:
        self.row = row
        self.provider = provider
        self.wire = _WIRES[row.key]

    def target(
        self,
        *,
        system_prompt: str | None = None,
        budgets: Budgets | None = None,
        timeout: float | None = None,
    ) -> EndpointTarget:
        return EndpointTarget(
            self.provider.url,
            "m",
            system_prompt=system_prompt,
            transport=self.wire.transport(self.provider.url, timeout),
            budgets=budgets,
        )

    def answer(self, text: str, tokens: Tokens = None) -> None:
        self.provider.script(self.wire.reply(text, tokens))

    def answer_tool_call(self, name: str, tokens: Tokens = None) -> None:
        if self.wire.tool_reply is None:
            raise AssertionError(f"{self.row.key} has no tool reply shape to script")
        self.provider.script(self.wire.tool_reply(name, tokens))

    def sent(self) -> list[dict[str, Any]]:
        return [r.body if isinstance(r.body, dict) else {} for r in self.provider.requests]


class _LangChainReply:
    """What a LangChain chat model hands back: content, calls, and maybe usage."""

    def __init__(
        self, content: str, tool_calls: Sequence[dict[str, Any]] = (), tokens: Tokens = None
    ) -> None:
        self.content = content
        self.tool_calls = list(tool_calls)
        if tokens is not None:
            self.usage_metadata = {"input_tokens": tokens[0], "output_tokens": tokens[1]}


class _ChatModel:
    """A LangChain chat-model double; `binds` decides whether `bind_tools` works."""

    model_name = "fake-chat"

    def __init__(self, *, binds: bool) -> None:
        self.binds = binds
        self.replies: list[_LangChainReply] = []
        self.seen: list[dict[str, Any]] = []

    def bind_tools(self, tools: Sequence[dict[str, Any]]) -> "_Bound":
        if not self.binds:
            raise NotImplementedError
        return _Bound(self, list(tools))

    def invoke(self, conversation: list[dict[str, Any]], /) -> object:
        return self.answer(conversation, [])

    def answer(self, conversation: list[dict[str, Any]], tools: list[dict[str, Any]]) -> object:
        self.seen.append({"messages": list(conversation), "tools": tools})
        return self.replies.pop(0)


@dataclass(frozen=True, slots=True)
class _Bound:
    model: _ChatModel
    tools: list[dict[str, Any]]

    def invoke(self, conversation: list[dict[str, Any]], /) -> object:
        return self.model.answer(conversation, self.tools)


class _LangChainHarness:
    """A LangChain chat-model double behind `langchain_target`."""

    def __init__(self, row: Row) -> None:
        self.row = row
        self.model = _ChatModel(binds=row.tools == CARRIED)

    def target(
        self, *, system_prompt: str | None = None, budgets: Budgets | None = None
    ) -> EndpointTarget:
        return langchain_target(self.model, system_prompt=system_prompt, budgets=budgets)

    def answer(self, text: str, tokens: Tokens = None) -> None:
        self.model.replies.append(_LangChainReply(text, tokens=tokens))

    def answer_tool_call(self, name: str, tokens: Tokens = None) -> None:
        call = {"name": name, "args": {}, "id": "call-1", "type": "tool_call"}
        self.model.replies.append(_LangChainReply("", tool_calls=[call], tokens=tokens))

    def sent(self) -> list[dict[str, Any]]:
        return self.model.seen


def _rows(predicate: Callable[[Row], bool]) -> pytest.MarkDecorator:
    """Run a test once per row the predicate selects, each through its own harness."""
    selected = [row for row in REQUIREMENTS if predicate(row)]
    return pytest.mark.parametrize("harness", selected, indirect=True, ids=_row_id)


def _row_id(row: Row) -> str:
    return row.key


def _is_http(row: Row) -> bool:
    return row.retried_statuses is not None


@pytest.fixture
def harness(request: pytest.FixtureRequest) -> Iterator[_Harness]:
    row: Row = request.param
    if not _is_http(row):
        yield _LangChainHarness(row)
        return
    with FakeProvider() as provider:
        yield _HttpHarness(row, provider)


@pytest.fixture(params=[row for row in REQUIREMENTS if _is_http(row)], ids=_row_id)
def http(request: pytest.FixtureRequest) -> Iterator[_HttpHarness]:
    with FakeProvider() as provider:
        yield _HttpHarness(request.param, provider)


@pytest.fixture
def slept(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", recorded.append)
    return recorded


def test_the_providers_page_prints_the_table_this_suite_enforces() -> None:
    page = (_REPO / "docs" / "providers.md").read_text(encoding="utf-8")

    assert render_table(REQUIREMENTS) in page


def test_every_cell_that_carries_nothing_names_its_refusal() -> None:
    for row in REQUIREMENTS:
        assert row.tools in {CARRIED, NO_TOOLS}
        assert row.tool_turns in {CARRIED, NO_TOOLS}
        assert row.token_usage in {CARRIED, NO_USAGE}


def _strings(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def _delivery(body: dict[str, Any]) -> str:
    """Name how the system message reached the model, from what was on the wire."""
    messages = body.get("messages")
    if isinstance(messages, list) and {"role": "system", "content": _SYSTEM} in messages:
        return "role"
    strings = list(_strings(body))
    if _SYSTEM in strings and _USER in strings:
        return "slot"
    if any(f"System: {_SYSTEM}" in s and f"User: {_USER}" in s for s in strings):
        return "folded"
    if any(f"system: {_SYSTEM}" in s and f"user: {_USER}" in s for s in strings):
        return "flattened"
    return "dropped"


@_rows(lambda row: True)
def test_the_system_message_arrives_as_the_table_says(harness: _Harness) -> None:
    harness.answer("ok")

    harness.target(system_prompt=_SYSTEM).chat(_HELLO)

    assert _delivery(harness.sent()[-1]) == harness.row.system_message


@_rows(lambda row: row.tools == CARRIED)
def test_offered_tools_reach_the_model_and_its_calls_come_back(harness: _Harness) -> None:
    harness.answer_tool_call("read_file")
    target = harness.target()

    reply = target.offer_tools(_HELLO, [_TOOL])

    assert Capability.CALL_TOOLS in target.capabilities()
    assert [call.name for call in reply.tool_calls] == ["read_file"]
    offered = harness.sent()[-1]["tools"]
    assert [tool["function"]["name"] for tool in offered] == ["read_file"]


@_rows(lambda row: row.tools == NO_TOOLS)
def test_without_tools_no_tool_capability_is_declared_and_nothing_is_sent(
    harness: _Harness,
) -> None:
    target = harness.target()

    assert Capability.CALL_TOOLS not in target.capabilities()
    with pytest.raises(EndpointError, match="tool calling"):
        target.offer_tools(_HELLO, [_TOOL])
    assert harness.sent() == []


def _carries_tool_turns(body: dict[str, Any]) -> bool:
    messages = body.get("messages")
    if not isinstance(messages, list):
        return False
    asked = any(
        m.get("role") == "assistant"
        and any(c.get("id") == "call-7" for c in m.get("tool_calls") or [])
        for m in messages
    )
    answered = any(m.get("role") == "tool" and m.get("tool_call_id") == "call-7" for m in messages)
    return asked and answered


@_rows(lambda row: row.tool_turns == CARRIED)
def test_tool_turns_in_history_reach_the_model(harness: _Harness) -> None:
    harness.answer("ok")

    harness.target().chat(_HISTORY)

    assert _carries_tool_turns(harness.sent()[-1])


@_rows(lambda row: row.tool_turns == NO_TOOLS)
def test_where_tool_turns_are_lost_no_tool_run_is_offered(harness: _Harness) -> None:
    harness.answer("ok")
    target = harness.target()

    target.chat(_HISTORY)

    assert "call-7" not in json.dumps(harness.sent()[-1])
    assert Capability.CALL_TOOLS not in target.capabilities()


@_rows(lambda row: row.token_usage != NO_USAGE)
def test_token_counts_are_read_when_sent_and_unknown_when_not(harness: _Harness) -> None:
    harness.answer("ok", tokens=(11, 7))
    harness.answer("ok")
    counted, silent = harness.target(), harness.target()

    counted.chat(_HELLO)
    silent.chat(_HELLO)

    assert (counted.usage().input_tokens, counted.usage().output_tokens) == (11, 7)
    assert counted.usage().requests_missing_token_counts == 0
    assert (silent.usage().input_tokens, silent.usage().output_tokens) == (None, None)
    assert silent.usage().requests_missing_token_counts == 1


@_rows(lambda row: row.token_usage != NO_USAGE)
def test_a_token_ceiling_is_accepted_where_counts_are_carried(harness: _Harness) -> None:
    harness.answer("ok", tokens=(11, 7))
    target = harness.target(budgets=Budgets(max_input_tokens=1000))

    assert target.chat(_HELLO) == "ok"


@_rows(lambda row: row.token_usage == NO_USAGE)
def test_a_token_ceiling_is_refused_where_counts_are_not_carried(harness: _Harness) -> None:
    target = harness.target()

    with pytest.raises(BudgetExhausted, match="cannot report token counts"):
        target.apply_budgets(Budgets(max_input_tokens=1000))
    assert harness.sent() == []

    harness.answer("ok", tokens=(11, 7))
    target.chat(_HELLO)
    assert target.usage().input_tokens is None
    assert target.usage().requests_missing_token_counts == 1


@_rows(lambda row: row.tools == CARRIED and row.token_usage == CARRIED)
def test_a_tool_turn_reads_its_token_counts(harness: _Harness) -> None:
    harness.answer_tool_call("read_file", tokens=(11, 7))
    target = harness.target(budgets=Budgets(max_input_tokens=1000))

    target.offer_tools(_HELLO, [_TOOL])

    assert (target.usage().input_tokens, target.usage().output_tokens) == (11, 7)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_refusal_status_fails_without_a_retry(
    http: _HttpHarness, slept: list[float], status: int
) -> None:
    http.provider.script(status_reply(status))
    target = http.target()

    with pytest.raises(HTTPError) as refused:
        target.chat(_HELLO)
    refused.value.close()

    assert refused.value.code == status
    assert len(http.provider.requests) == 1
    assert target.usage().requests == 1
    assert slept == []


@pytest.mark.parametrize("status", _BUILT_IN_RETRIES)
def test_a_transient_status_is_retried_exactly_where_the_table_says(
    http: _HttpHarness, slept: list[float], status: int
) -> None:
    http.provider.script(status_reply(status, retry_after="0"))
    http.answer("recovered")
    target = http.target()

    if status in (http.row.retried_statuses or ()):
        assert target.chat(_HELLO) == "recovered"
        assert len(http.provider.requests) == 2
        assert target.usage().requests == 2
    else:
        with pytest.raises(HTTPError) as failed:
            target.chat(_HELLO)
        failed.value.close()
        assert failed.value.code == status
        assert len(http.provider.requests) == 1
        assert target.usage().requests == 1


def test_retry_after_is_honoured(http: _HttpHarness, slept: list[float]) -> None:
    http.provider.script(status_reply(429, retry_after="7"))
    http.answer("recovered")

    assert http.target().chat(_HELLO) == "recovered"
    assert slept == [7.0]


def test_a_retry_is_refused_by_the_request_ceiling(http: _HttpHarness, slept: list[float]) -> None:
    http.provider.script(status_reply(429, retry_after="0"))
    target = http.target(budgets=Budgets(max_requests=1))

    with pytest.raises(BudgetExhausted):
        target.chat(_HELLO)

    assert len(http.provider.requests) == 1
    assert target.usage().requests == 1


def test_a_redirect_is_refused_and_not_followed(http: _HttpHarness) -> None:
    http.provider.script(redirect_reply(f"{http.provider.url}/elsewhere"))

    with pytest.raises(EndpointError, match="redirect"):
        http.target().chat(_HELLO)

    assert len(http.provider.requests) == 1


def test_malformed_json_fails_closed(http: _HttpHarness) -> None:
    http.provider.script(malformed_reply())

    with pytest.raises(EndpointError, match="non-JSON"):
        http.target().chat(_HELLO)


def test_a_reply_missing_its_text_fails_closed(http: _HttpHarness) -> None:
    http.provider.script(http.wire.missing_field)

    with pytest.raises(EndpointError):
        http.target().chat(_HELLO)


def test_an_oversized_reply_is_refused(http: _HttpHarness) -> None:
    http.provider.script(oversized_reply(8 * 1024 * 1024 + 1))

    with pytest.raises(EndpointError, match="exceeds"):
        http.target().chat(_HELLO)


def test_a_slow_reply_times_out(http: _HttpHarness) -> None:
    http.provider.script(delayed(http.wire.reply("too late", None), 5.0))
    target = http.target(timeout=0.2)

    with pytest.raises(EndpointUnreachable, match=r"did not answer within 0\.2 seconds"):
        target.chat(_HELLO)

    assert target.usage().requests == 1
