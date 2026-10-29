"""The HTTP clients that talk to a model, an adapted product endpoint and a collector.

Real loopback sockets rather than doubles, because the behaviour under test lives in
urllib: a double of `urlopen` proves nothing about whether urllib follows a `302`.

Two promises are pinned here. A reply always comes from the address that was
configured — a redirect is never followed, so a POST cannot turn into a GET to
somebody else carrying the operator's credential, with that host's answer graded as
the model's. And every request that leaves the machine is counted against the
run's ceiling and in its usage, retries included.
"""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.error import HTTPError

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.report.result import ScanResult
from guardana.core.reporter import HttpReporter, UnacknowledgedSubmissionError
from guardana.core.target.adapter import AdapterConfig, HttpAdapterTransport
from guardana.core.target.endpoint import (
    ChatMessage,
    EndpointError,
    EndpointTarget,
    post_json,
)

_CHAT_REPLY = {"choices": [{"message": {"content": "I cannot help with that."}}], "reply": "no"}
_HELLO = [ChatMessage(role="user", content="hello")]


class _Elsewhere(BaseHTTPRequestHandler):
    """A second origin that writes down every request it is sent, and answers all of them."""

    protocol_version = "HTTP/1.1"
    received: ClassVar[list[tuple[str, str | None]]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a request log per assertion is unreadable."""

    def _answer(self) -> None:
        type(self).received.append((self.command, self.headers.get("Authorization")))
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = json.dumps(_CHAT_REPLY).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        """Answer a followed redirect as a model would."""
        self._answer()

    def do_POST(self) -> None:
        """Answer a request sent here directly."""
        self._answer()


class _Redirector(BaseHTTPRequestHandler):
    """The configured endpoint: it answers every POST with a `302` to `_Elsewhere`."""

    protocol_version = "HTTP/1.1"
    location = ""

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a request log per assertion is unreadable."""

    def do_POST(self) -> None:
        """Send the caller to another origin."""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _RateLimited(BaseHTTPRequestHandler):
    """Answers `429` until it has refused `refusals` requests, then a chat reply."""

    protocol_version = "HTTP/1.1"
    refusals = 2
    seen: ClassVar[list[int]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        """Stay quiet; a request log per assertion is unreadable."""

    def do_POST(self) -> None:
        """Refuse, or answer once the refusals are spent."""
        type(self).seen.append(1)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if len(type(self).seen) <= type(self).refusals:
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(_CHAT_REPLY).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    """A second loopback origin that records what reaches it."""
    _Elsewhere.received = []
    yield from _serve(_Elsewhere)


@pytest.fixture
def redirecting(elsewhere: str) -> Iterator[str]:
    """A configured endpoint that redirects every POST to `elsewhere`."""
    _Redirector.location = f"{elsewhere}/v1/chat/completions"
    yield from _serve(_Redirector)


@pytest.fixture
def rate_limited() -> Iterator[str]:
    """An endpoint that refuses twice with `429`, then answers."""
    _RateLimited.seen = []
    _RateLimited.refusals = 2
    yield from _serve(_RateLimited)


def test_a_model_endpoint_that_redirects_is_unavailable_and_the_other_host_hears_nothing(
    redirecting: str, elsewhere: str
) -> None:
    with pytest.raises(EndpointError, match="redirect"):
        post_json(f"{redirecting}/v1/chat/completions", {}, "operator-token", "ref")

    assert _Elsewhere.received == []


def test_a_model_endpoint_that_answers_directly_is_still_read(elsewhere: str) -> None:
    assert post_json(f"{elsewhere}/v1/chat/completions", {}, None, "ref") == _CHAT_REPLY
    assert _Elsewhere.received == [("POST", None)]


def test_an_adapted_endpoint_that_redirects_is_unavailable_and_the_other_host_hears_nothing(
    redirecting: str, elsewhere: str
) -> None:
    transport = HttpAdapterTransport(
        AdapterConfig(
            url=f"{redirecting}/chat",
            body={"message": "{{prompt}}"},
            response_path="reply",
            headers={"Authorization": "Bearer operator-token"},
        )
    )

    with pytest.raises(EndpointError, match="redirect"):
        transport.send("", "", _HELLO, None)

    assert _Elsewhere.received == []


def test_an_adapted_endpoint_that_answers_directly_is_still_read(elsewhere: str) -> None:
    transport = HttpAdapterTransport(
        AdapterConfig(url=f"{elsewhere}/chat", body={"m": "{{prompt}}"}, response_path="reply")
    )

    assert transport.send("", "", _HELLO, None) == "no"


def test_a_collector_that_redirects_is_a_rejected_submission_and_the_other_host_hears_nothing(
    redirecting: str, elsewhere: str
) -> None:
    reporter = HttpReporter(f"{redirecting}/findings", api_key="collector-key")

    with pytest.raises(HTTPError) as rejected:
        reporter.submit(ScanResult((), (), ()), source="ci")
    rejected.value.close()

    assert rejected.value.code == 302
    assert _Elsewhere.received == []


def test_a_collector_that_answers_directly_still_receives_the_envelope(elsewhere: str) -> None:
    # The double answers as a model would, which is not a collector's acknowledgement.
    with pytest.raises(UnacknowledgedSubmissionError):
        HttpReporter(f"{elsewhere}/findings").submit(ScanResult((), (), ()), source="ci")

    assert _Elsewhere.received == [("POST", None)]


def test_a_retried_request_counts_against_the_request_ceiling(
    rate_limited: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _seconds: None)
    target = EndpointTarget(rate_limited, "m", budgets=Budgets(max_requests=1))

    with pytest.raises(BudgetExhausted):
        target.chat(_HELLO)

    assert len(_RateLimited.seen) == 1
    assert target.usage().requests == 1


def test_every_attempt_a_retry_sends_is_in_the_usage(
    rate_limited: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _seconds: None)
    target = EndpointTarget(rate_limited, "m")

    assert target.chat(_HELLO) == "I cannot help with that."

    assert len(_RateLimited.seen) == 3
    assert target.usage().requests == 3


def test_a_retry_that_never_succeeds_still_counts_every_attempt(
    rate_limited: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _seconds: None)
    _RateLimited.refusals = 10
    target = EndpointTarget(rate_limited, "m")

    with pytest.raises(HTTPError) as refused:
        target.chat(_HELLO)
    refused.value.close()

    assert target.usage().requests == len(_RateLimited.seen) == 3


def test_a_request_ceiling_with_room_for_the_retries_lets_them_through(
    rate_limited: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _seconds: None)
    target = EndpointTarget(rate_limited, "m", budgets=Budgets(max_requests=3))

    assert target.chat(_HELLO) == "I cannot help with that."
    assert target.usage().requests == 3
