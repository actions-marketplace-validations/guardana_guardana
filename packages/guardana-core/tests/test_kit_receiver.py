"""The kit's receiver gives an HTTP reporter one destination per status it must report.

Each URL is checked by a plain request, not by a reporter, so a reporter's own
reading of an answer cannot make the receiver look right.
"""

import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

import pytest
from guardana.core.testing import receiver

_DIRECT = build_opener(ProxyHandler({}))


def _post(url: str, body: bytes = b"{}") -> int:
    request = Request(url, data=body, method="POST")  # noqa: S310 — a loopback URL the test made
    with _DIRECT.open(request, timeout=5) as response:
        status: int = response.status
        return status


def test_the_accepting_url_answers_2xx_and_records_what_it_received() -> None:
    with receiver() as served:
        status = _post(served.accepting, b'{"run": 1}')

        assert 200 <= status < 300
        assert [r.body for r in served.received] == [b'{"run": 1}']
        assert served.received[0].method == "POST"


def test_the_refusing_url_answers_403() -> None:
    with receiver() as served, pytest.raises(HTTPError) as refused:
        _post(served.refusing)

    refused.value.close()
    assert refused.value.code == 403


def test_the_closed_url_is_on_a_port_nothing_answers() -> None:
    with receiver() as served:
        with pytest.raises(URLError) as unanswered:
            _post(served.closed)

        assert isinstance(unanswered.value.reason, ConnectionRefusedError)


def test_every_url_is_on_the_loopback_interface() -> None:
    with receiver() as served:
        urls = (served.accepting, served.refusing, served.closed)

    assert {urlsplit(url).hostname for url in urls} == {"127.0.0.1"}
    assert urlsplit(served.accepting).port != urlsplit(served.closed).port


def test_the_server_is_gone_once_the_block_ends() -> None:
    with receiver() as served:
        port = urlsplit(served.accepting).port

    assert port is not None
    with socket.socket() as attempt, pytest.raises(ConnectionRefusedError):
        attempt.connect(("127.0.0.1", port))
