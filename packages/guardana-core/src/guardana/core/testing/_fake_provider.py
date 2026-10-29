"""A local HTTP double of a model provider, scripted request by request.

It speaks the reply shapes the built-in transports read (OpenAI chat completions,
Ollama `/api/chat`, TGI `/generate`) and the shape an adapted product endpoint is
configured for, a guard's decline and metadata included, and it fails on cue: a status
with `Retry-After`, a redirect, malformed JSON, a missing field, an oversized body, a
slow reply. Every request is
recorded as it arrived, so a test asserts on what reached the wire rather than on
what the client meant to send.

Private until its interface settles; tests import it by its module path.
"""

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Self

_NOTHING_SCRIPTED = 501
"""Answered when the script is empty: loud, and outside every status a client retries."""


@dataclass(frozen=True, slots=True)
class Scripted:
    """One scripted answer: a status, its headers, a body, and a wait before sending it."""

    status: int = 200
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    delay_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    """One request as the double received it.

    `headers` are keyed in lower case. `body` is the parsed JSON, or None when the
    request carried no JSON.
    """

    method: str
    path: str
    headers: Mapping[str, str]
    body: object


def json_reply(payload: object, *, status: int = 200) -> Scripted:
    """Answer with `payload` serialized as JSON."""
    return Scripted(
        status=status,
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def openai_reply(
    text: str | None,
    *,
    usage: Mapping[str, int] | None = None,
    tool_calls: list[dict[str, object]] | None = None,
) -> Scripted:
    """Answer in the OpenAI chat-completions shape."""
    message: dict[str, object] = {"role": "assistant", "content": text}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    payload: dict[str, object] = {"choices": [{"message": message}]}
    if usage is not None:
        payload["usage"] = dict(usage)
    return json_reply(payload)


def ollama_reply(
    text: str, *, prompt_eval_count: int | None = None, eval_count: int | None = None
) -> Scripted:
    """Answer in Ollama's native `/api/chat` shape, with its token counts when given."""
    payload: dict[str, object] = {
        "message": {"role": "assistant", "content": text},
        "done": True,
    }
    if prompt_eval_count is not None:
        payload["prompt_eval_count"] = prompt_eval_count
    if eval_count is not None:
        payload["eval_count"] = eval_count
    return json_reply(payload)


def tgi_reply(text: str) -> Scripted:
    """Answer in TGI's `/generate` shape."""
    return json_reply({"generated_text": text})


def adapter_reply(
    text: str | None,
    *,
    fields: Mapping[str, object] | None = None,
    status: int = 200,
) -> Scripted:
    """Answer in the shape an adapter configured with `response_path: data.reply` reads.

    `text` None leaves `data.reply` out, as a guard that withheld the answer does.
    `fields` sit beside `data` at the top level, where a guard's verdict, an error code or
    a request id would; with `status` outside `2xx` this is a guard's JSON decline.
    """
    payload: dict[str, object] = {"data": {} if text is None else {"reply": text}}
    payload.update(fields or {})
    return json_reply(payload, status=status)


def status_reply(status: int, *, retry_after: str | None = None) -> Scripted:
    """Answer with a bare error status, optionally asking the client to wait."""
    headers = {"Content-Type": "application/json"}
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return Scripted(status=status, body=b'{"error": "scripted"}', headers=headers)


def redirect_reply(location: str, *, status: int = 302) -> Scripted:
    """Answer with a redirect to `location`."""
    return Scripted(status=status, headers={"Location": location})


def malformed_reply() -> Scripted:
    """Answer 200 with a body that is not JSON."""
    return Scripted(body=b'{"choices": [', headers={"Content-Type": "application/json"})


def oversized_reply(size: int) -> Scripted:
    """Answer 200 with a body of `size` bytes."""
    return Scripted(body=b" " * size, headers={"Content-Type": "application/json"})


def delayed(reply: Scripted, seconds: float) -> Scripted:
    """Send `reply` only after `seconds` have passed."""
    return replace(reply, delay_seconds=seconds)


class FakeProvider:
    """A provider double on `127.0.0.1`, answering each request with the next scripted reply.

    The last reply repeats once the script runs out, so a status that never clears
    is one entry. An empty script answers `501`, which no client retries.
    """

    def __init__(self, *replies: Scripted) -> None:
        self._script = list(replies)
        self._last: Scripted | None = None
        self._lock = threading.Lock()
        self._closing = threading.Event()
        self.requests: list[RecordedRequest] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(self))
        # The poll interval bounds how long `shutdown` waits, which every test pays once.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    @property
    def url(self) -> str:
        """The base URL the double answers on."""
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def script(self, *replies: Scripted) -> None:
        """Append replies to the script."""
        with self._lock:
            self._script.extend(replies)

    def __enter__(self) -> Self:
        """Start serving."""
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop serving, cutting short any scripted delay still running."""
        self._closing.set()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def _answer(self, request: RecordedRequest) -> Scripted:
        with self._lock:
            self.requests.append(request)
            if self._script:
                self._last = self._script.pop(0)
            if self._last is None:
                return Scripted(status=_NOTHING_SCRIPTED, body=b"nothing scripted")
            return self._last

    def _wait(self, seconds: float) -> None:
        self._closing.wait(seconds)


def _handler_for(provider: FakeProvider) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — the base signature
            """Stay quiet; a request log per test is noise."""

        def do_POST(self) -> None:
            """Record the request and send the scripted reply."""
            self._respond()

        def do_GET(self) -> None:
            """Record the request and send the scripted reply."""
            self._respond()

        def _respond(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body: object = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                body = None
            reply = provider._answer(  # noqa: SLF001 — the double's own handler
                RecordedRequest(
                    method=self.command,
                    path=self.path,
                    headers={key.lower(): value for key, value in self.headers.items()},
                    body=body,
                )
            )
            if reply.delay_seconds:
                provider._wait(reply.delay_seconds)  # noqa: SLF001 — the double's own handler
            try:
                self.send_response(reply.status)
                for name, value in reply.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(reply.body)))
                self.end_headers()
                self.wfile.write(reply.body)
            except (BrokenPipeError, ConnectionResetError):
                return  # the client gave up waiting, which is what a timeout test wants

    return _Handler
