"""`probe` against a real loopback endpoint: what it follows, what it counts, when it stops.

A socket rather than a transport double, because each of these lived in the HTTP
client a double replaces: urllib following a `302` as a GET to another origin, a
retry sending three requests inside one budget claim, and a reply without token
counts slipping past a token ceiling.
"""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_REFUSAL = {"choices": [{"message": {"content": "I can't help with that."}}]}


def _reply(handler: BaseHTTPRequestHandler, status: int, payload: object = None) -> None:
    length = int(handler.headers.get("Content-Length") or 0)
    if length:
        handler.rfile.read(length)
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Retry-After", "0")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _Elsewhere(BaseHTTPRequestHandler):
    """Another origin, answering everything as a model that refuses would."""

    protocol_version = "HTTP/1.1"
    received: ClassVar[list[str | None]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a request log per assertion is unreadable."""

    def do_GET(self) -> None:
        """Answer a followed redirect."""
        type(self).received.append(self.headers.get("Authorization"))
        _reply(self, 200, _REFUSAL)

    def do_POST(self) -> None:
        """Answer a request sent here directly."""
        type(self).received.append(self.headers.get("Authorization"))
        _reply(self, 200, _REFUSAL)


class _Redirector(BaseHTTPRequestHandler):
    """The endpoint named on the command line; it redirects every request."""

    protocol_version = "HTTP/1.1"
    location = ""

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a request log per assertion is unreadable."""

    def do_POST(self) -> None:
        """Point the caller at another origin."""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _Model(BaseHTTPRequestHandler):
    """A model that refuses `limited` times with `429`, then answers without usage."""

    protocol_version = "HTTP/1.1"
    limited = 0
    seen: ClassVar[list[int]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a request log per assertion is unreadable."""

    def do_POST(self) -> None:
        """Rate-limit, or answer with no token counts."""
        type(self).seen.append(1)
        if len(type(self).seen) <= type(self).limited:
            _reply(self, 429)
            return
        _reply(self, 200, _REFUSAL)


def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def elsewhere() -> Iterator[str]:
    """A second loopback origin that records every request reaching it."""
    _Elsewhere.received = []
    yield from _serve(_Elsewhere)


@pytest.fixture
def redirecting(elsewhere: str) -> Iterator[str]:
    """An endpoint redirecting every POST to `elsewhere`."""
    _Redirector.location = f"{elsewhere}/v1/chat/completions"
    yield from _serve(_Redirector)


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A loopback model; tests set how many requests it rate-limits first."""
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _seconds: None)
    _Model.seen = []
    _Model.limited = 0
    yield from _serve(_Model)


def _probe(url: str, tmp_path: Path, *flags: str) -> int:
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            url,
            "--model",
            "m",
            "--concurrency",
            "1",
            "--format",
            "json",
            "--output",
            str(tmp_path / "run.json"),
            "--api-key-env",
            "GUARDANA_TEST_ENDPOINT_KEY",
            *flags,
        ],
        env={"GUARDANA_TEST_ENDPOINT_KEY": "operator-token"},
    )
    return result.exit_code


def test_an_endpoint_that_redirects_is_unavailable_and_the_other_origin_hears_nothing(
    redirecting: str, elsewhere: str, tmp_path: Path
) -> None:
    assert _probe(redirecting, tmp_path) == ExitCode.TARGET_UNAVAILABLE
    assert _Elsewhere.received == []


def test_a_token_ceiling_over_replies_without_token_counts_stops_at_the_first(
    model: str, tmp_path: Path
) -> None:
    assert _probe(model, tmp_path, "--max-input-tokens", "1") == ExitCode.BUDGET_EXHAUSTED
    assert len(_Model.seen) == 1


def test_a_request_ceiling_counts_every_retried_attempt(model: str, tmp_path: Path) -> None:
    _Model.limited = 2

    assert _probe(model, tmp_path, "--max-requests", "1") == ExitCode.BUDGET_EXHAUSTED
    assert len(_Model.seen) == 1
