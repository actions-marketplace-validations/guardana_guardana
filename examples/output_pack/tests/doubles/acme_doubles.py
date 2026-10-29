"""A scripted model endpoint and a webhook receiver Guardana did not write.

The receiver checks every delivery with `standardwebhooks`, the specification's
reference verifier, which only this suite installs; the package never imports it.
"""

import base64
import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from standardwebhooks.webhooks import Webhook

SECRET = "whsec_" + base64.b64encode(b"acme webhook test key only").decode("ascii")
"""A signing key assembled at run time, so no secret-shaped literal is written down."""

ADMIT = ("--plugins", "allowlist", "--allow-plugin", "acme-guardana-outputs")
"""The plugin trust that admits this package and nothing else."""


@contextmanager
def _serving(handler: type[BaseHTTPRequestHandler]) -> Iterator[int]:
    """Serve `handler` on a free loopback port and yield the port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class _Quiet(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — the base signature
        """Stay quiet; a request log per test is noise."""


@dataclass
class ModelEndpoint:
    """An OpenAI-compatible endpoint whose every reply comes from `answer`."""

    url: str
    answer: Callable[[str], str]
    requests: list[str] = field(default_factory=list)


@contextmanager
def serving_model() -> Iterator[ModelEndpoint]:
    """Serve a chat-completions endpoint that answers the last user message by `answer`."""
    endpoint = ModelEndpoint(url="", answer=lambda _question: "")

    class Handler(_Quiet):
        def do_POST(self) -> None:
            """Answer in the chat-completions shape."""
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            messages: list[dict[str, Any]] = json.loads(raw)["messages"]
            question = str(messages[-1]["content"])
            endpoint.requests.append(question)
            message = {"role": "assistant", "content": endpoint.answer(question)}
            body = json.dumps({"choices": [{"message": message}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with _serving(Handler) as port:
        endpoint.url = f"http://127.0.0.1:{port}/v1"
        yield endpoint


@dataclass(frozen=True)
class Received:
    """One delivery as the receiver saw it."""

    webhook_id: str
    verified: bool
    payload: dict[str, Any] | None
    answered: int


@dataclass
class Receiver:
    """A webhook receiver answering each delivery with the next scripted status."""

    url: str
    secret: str
    script: list[int]
    retry_after: str | None = None
    """Sent as `Retry-After` with every answer that is not `2xx`, when set."""

    received: list[Received] = field(default_factory=list)

    @property
    def origin(self) -> str:
        """`scheme://host:port`, as the delivery line shows the destination."""
        return self.url.rsplit("/", 1)[0]


@contextmanager
def serving_receiver() -> Iterator[Receiver]:
    """Serve a receiver that verifies every delivery before it answers.

    A delivery the reference verifier refuses is answered `401`, whatever the script
    says; the script's last status repeats once it runs out.
    """
    state = Receiver(url="", secret=SECRET, script=[204])
    lock = threading.Lock()

    class Handler(_Quiet):
        def do_POST(self) -> None:
            """Verify the delivery, then answer by script."""
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            headers = {key.lower(): value for key, value in self.headers.items()}
            try:
                payload: dict[str, Any] | None = Webhook(state.secret).verify(body, headers)
            except Exception:
                payload = None
            with lock:
                status = state.script.pop(0) if len(state.script) > 1 else state.script[0]
                if payload is None:
                    status = 401
                state.received.append(
                    Received(headers.get("webhook-id", ""), payload is not None, payload, status)
                )
            self.send_response(status)
            if state.retry_after is not None and not 200 <= status < 300:
                self.send_header("Retry-After", state.retry_after)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with _serving(Handler) as port:
        state.url = f"http://127.0.0.1:{port}/hook"
        yield state
