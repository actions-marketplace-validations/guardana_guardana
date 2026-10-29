"""Every collector response tells the browser not to guess its content type.

The JSON routes echo submitted, attacker-influenced text; without `nosniff` a
browser may sniff such a body as HTML when it is opened directly.
"""

from collections.abc import Mapping

import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.store import InMemoryStore
from guardana.server.tenancy import TenantScope

_OK = 200
_NOT_FOUND = 404
_UNPROCESSABLE = 422
_TOO_LARGE = 413
_SERVER_ERROR = 500
_LEAKED = "connection to db.internal:5432 refused for user collector"


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), dashboard=True, allow_unauthenticated=True))


def _assert_nosniff(headers: Mapping[str, str]) -> None:
    assert headers.get("x-content-type-options") == "nosniff", dict(headers)


@pytest.mark.parametrize("path", ["/findings", "/trend", "/stats", "/catalog", "/healthz"])
def test_json_routes_send_nosniff(path: str) -> None:
    response = _client().get(path)

    assert response.headers["content-type"].startswith("application/json")
    _assert_nosniff(response.headers)


def test_an_accepted_submission_sends_nosniff() -> None:
    accepted = _client().post("/findings", json={"schema_version": 2, "source": "ci"})

    assert accepted.status_code == _OK
    _assert_nosniff(accepted.headers)


def test_error_responses_send_nosniff() -> None:
    client = _client()

    missing = client.get("/no-such-route")
    malformed = client.post("/findings", json={"source": 7})

    assert missing.status_code == _NOT_FOUND
    assert malformed.status_code == _UNPROCESSABLE
    _assert_nosniff(missing.headers)
    _assert_nosniff(malformed.headers)


def test_a_refusal_from_the_limits_sends_nosniff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "1024")
    client = _client()

    refused = client.post("/findings", content=b"x" * 4096)

    assert refused.status_code == _TOO_LARGE
    _assert_nosniff(refused.headers)


class _FailingStore(InMemoryStore):
    """A store whose trend query fails with text that must never reach the caller."""

    def trend(self, scope: TenantScope) -> dict[str, int]:
        raise RuntimeError(_LEAKED)


def test_an_unhandled_exception_answers_500_with_nosniff_and_no_exception_text() -> None:
    app = create_app(store=_FailingStore(), allow_unauthenticated=True)
    client = TestClient(app, raise_server_exceptions=False)

    failed = client.get("/trend")

    assert failed.status_code == _SERVER_ERROR
    _assert_nosniff(failed.headers)
    assert failed.headers["content-type"].startswith("application/json")
    assert _LEAKED not in failed.text
    assert "RuntimeError" not in failed.text


def test_an_unhandled_exception_is_still_raised_for_the_server_to_log() -> None:
    client = TestClient(create_app(store=_FailingStore(), allow_unauthenticated=True))

    with pytest.raises(RuntimeError, match=_LEAKED):
        client.get("/trend")


@pytest.mark.parametrize("path", ["/", "/healthz", "/readyz"])
def test_head_on_a_public_page_answers_like_get_without_a_body(path: str) -> None:
    client = _client()

    get = client.get(path)
    head = client.head(path)

    assert head.status_code == get.status_code == _OK
    assert head.content == b""
    assert dict(head.headers) == dict(get.headers)


def test_head_on_the_dashboard_carries_its_security_headers() -> None:
    head = _client().head("/")

    assert "content-security-policy" in head.headers
    assert head.headers["referrer-policy"] == "no-referrer"
    _assert_nosniff(head.headers)
