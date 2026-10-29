"""Rotating a collector key, step by step as `docs/deployment.md` describes it.

Issue a second key, move the pipeline to it, revoke the first, and confirm the
first is refused. Driven through `guardana-collector`, the command an operator
types, and checked through the route a pipeline calls: a rotation is finished when
the old credential answers `401`, not when a column says revoked. Rotation changes
who may write; it must not touch what was written.
"""

import psycopg
import pytest
from conftest import _submission
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.cli import EXIT_OK, main
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, resolve_project

_OK = 200
_UNAUTHORIZED = 401
_UNPROCESSABLE = 422


def _token_printed(capsys: pytest.CaptureFixture[str]) -> str:
    return next(word for word in capsys.readouterr().out.split() if word.startswith("gdn_"))


def _send(client: TestClient, token: str, source: str) -> int:
    response = client.post(
        "/findings",
        json=_submission(source).model_dump(mode="json"),
        headers={"Authorization": f"Bearer {token}"},
    )
    return response.status_code


def _confirm(client: TestClient, token: str) -> int:
    """The runbook's confirmation: an empty body, which no key can store anything with."""
    response = client.post("/findings", json={}, headers={"Authorization": f"Bearer {token}"})
    return response.status_code


def test_a_rotated_key_writes_and_the_revoked_one_is_refused(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.delenv("GUARDANA_MIGRATE_ON_START", raising=False)
    assert main(["migrate"]) == EXIT_OK
    capsys.readouterr()
    assert main(["bootstrap", "--org", "acme", "--project", "web"]) == EXIT_OK
    old = _token_printed(capsys)
    client = TestClient(create_app())
    assert _send(client, old, "before-rotation") == _OK

    assert main(["key", "create", "--project", "acme/web", "--name", "ci-next"]) == EXIT_OK
    new = _token_printed(capsys)

    assert _send(client, new, "during-rotation") == _OK
    assert _send(client, old, "during-rotation") == _OK, "the old key stops only when revoked"

    assert main(["key", "revoke", old.split("_")[1]]) == EXIT_OK

    assert _send(client, old, "after-revocation") == _UNAUTHORIZED
    assert _send(client, new, "after-rotation") == _OK
    assert _confirm(client, old) == _UNAUTHORIZED
    assert _confirm(client, new) == _UNPROCESSABLE, "a working key is told the body is empty"

    with psycopg.connect(database_url) as connection:
        project = resolve_project(connection, "acme/web")
    held = PostgresStore(database_url).submissions(TenantScope.for_project(project.id))
    assert [submission.source for submission in held] == [
        "before-rotation",
        "during-rotation",
        "during-rotation",
        "after-rotation",
    ]
    assert all(submission.findings for submission in held)


def test_the_listing_shows_which_key_was_revoked(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The confirmation step an operator reads, before checking the `401`."""
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    main(["bootstrap", "--org", "acme", "--project", "web"])
    old = _token_printed(capsys)
    main(["key", "create", "--project", "acme/web", "--name", "ci-next"])
    new = _token_printed(capsys)
    main(["key", "revoke", old.split("_")[1]])
    capsys.readouterr()

    main(["key", "list", "--project", "acme/web"])

    listed = {line.split()[0]: line.split()[1] for line in capsys.readouterr().out.splitlines()}
    assert listed == {old.split("_")[1]: "revoked", new.split("_")[1]: "active"}
