"""No failure to open a database connection carries the connection string's password.

libpq quotes a connection string it cannot parse back in its error. Each place the
collector opens a connection is driven here with one it cannot parse; none needs a
running PostgreSQL.
"""

import traceback

import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.db.connection import DatabaseUnreachableError, connect, without_password

_UNAVAILABLE = 503
_URLS = [
    "postgresql://nobody:hunter2@[::1/nothing",
    "postgresql://nobody:hunter%32@[::1/nothing",
    "host=127.0.0.1 password=hunter2 port=1 dbname='nothing",
    "postgresql://nobody@127.0.0.1:1/nothing?password=hunter2%zz&connect_timeout=1",
]


def _leaks(text: str) -> bool:
    return "hunter" in text


@pytest.mark.parametrize("url", _URLS)
def test_a_connection_that_cannot_open_names_no_password_even_in_its_traceback(url: str) -> None:
    with pytest.raises(DatabaseUnreachableError) as raised:
        connect(url)

    assert not _leaks("".join(traceback.format_exception(raised.value)))


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("postgresql://u@h/db?password=hunter2&next=1", 'bad option: "hunter2"'),
        ("postgresql://u@h/db?password=hunter2%zz&next=1", 'bad token: "hunter2%zz"'),
        ("postgresql://u@h/db?password=hunter2#frag", 'bad value: "hunter2"'),
        ("host=h password=hunter2&more port=1", 'bad value: "hunter2&more"'),
    ],
)
def test_a_query_password_is_withheld_up_to_the_next_parameter(url: str, message: str) -> None:
    assert not _leaks(without_password(message, url))


def test_a_message_that_never_quoted_the_password_is_left_as_it_was() -> None:
    message = 'connection to server at "127.0.0.1", port 1 failed'

    assert without_password(message, "postgresql://u:pw@127.0.0.1:1/db") == message


@pytest.mark.parametrize("url", _URLS)
def test_readiness_logs_no_password(
    url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", url)
    client = TestClient(create_app())

    assert client.get("/readyz").status_code == _UNAVAILABLE
    logged = capsys.readouterr().err
    assert "readiness check failed" in logged
    assert not _leaks(logged)


@pytest.mark.parametrize("url", _URLS)
def test_authentication_logs_no_password(
    url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", url)
    client = TestClient(create_app())

    response = client.get("/findings", headers={"Authorization": "Bearer gdn_x"})

    assert response.status_code == _UNAVAILABLE
    logged = capsys.readouterr().err
    assert "authentication could not reach the database" in logged
    assert not _leaks(logged)


@pytest.mark.parametrize("url", _URLS)
def test_migrating_on_start_fails_without_the_password_in_its_traceback(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", url)
    monkeypatch.setenv("GUARDANA_MIGRATE_ON_START", "1")

    with pytest.raises(DatabaseUnreachableError) as raised:
        create_app()

    assert not _leaks("".join(traceback.format_exception(raised.value)))


@pytest.mark.parametrize("url", _URLS)
def test_a_session_sign_in_fails_without_the_password_in_its_traceback(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", url)
    client = TestClient(create_app(dashboard=True))

    with pytest.raises(DatabaseUnreachableError) as raised:
        client.post("/session", json={"token": "gdn_x"})

    assert not _leaks("".join(traceback.format_exception(raised.value)))
