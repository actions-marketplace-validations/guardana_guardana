"""Every envelope a published release wrote, sent to this collector and read back.

`packages/guardana-core/tests/historical/envelope/` holds what each release POSTed
when it was fed synthetic input, kept whenever the shape changed. A collector
promises to accept every version from 2 up to its own, so a fleet can upgrade one
agent at a time; these documents are the only evidence of that promise that was
not written by the code making it. Each goes through the real route, under a real
key, into PostgreSQL, and comes back through the scoped store the server reads with.
"""

import json
from pathlib import Path
from typing import Any, NamedTuple

import psycopg
import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.auth import Scope, generate_key, store_key
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS, Submission
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, create_organization, create_project

HISTORICAL = Path(__file__).resolve().parents[3] / "packages/guardana-core/tests/historical"

_OK = 200
_UNPROCESSABLE = 422


def stored_envelopes() -> list[tuple[str, dict[str, Any]]]:
    """Every stored envelope as `(file name, document)`, oldest version first."""
    documents: list[tuple[str, dict[str, Any]]] = []
    for path in (HISTORICAL / "envelope").glob("*.json"):
        document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        documents.append((path.name, document))
    if not documents:
        raise AssertionError(f"{HISTORICAL / 'envelope'} holds no envelope")
    return sorted(documents, key=lambda entry: (int(entry[1]["schema_version"]), entry[0]))


_ENVELOPES = stored_envelopes()


class Collector(NamedTuple):
    """A collector serving a migrated database, and one key that may write and read it."""

    client: TestClient
    token: str
    store: PostgresStore
    scope: TenantScope


def issue_key(database_url: str, project_id: int, name: str = "ci") -> str:
    """Store a key that writes and reads one project, and return the token, once."""
    issued, secret_hash = generate_key(name, (Scope.INGEST, Scope.READ))
    with psycopg.connect(database_url) as connection:
        store_key(connection, issued, secret_hash, scope=TenantScope.for_project(project_id))
    return issued.token


def serve(
    database_url: str, project_id: int, monkeypatch: pytest.MonkeyPatch, *, token: str | None = None
) -> Collector:
    """The collector as it is deployed: storage from the environment, nothing migrated on start.

    Without a `token`, a new key for the project is issued.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.delenv("GUARDANA_MIGRATE_ON_START", raising=False)
    return Collector(
        client=TestClient(create_app()),
        token=token if token is not None else issue_key(database_url, project_id),
        store=PostgresStore(database_url),
        scope=TenantScope.for_project(project_id),
    )


def bearer(token: str) -> dict[str, str]:
    """The header a pipeline sends its key in."""
    return {"Authorization": f"Bearer {token}"}


def tenant(database_url: str) -> int:
    """Create the one organization and project the stored envelopes are sent into."""
    with psycopg.connect(database_url) as connection:
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
        connection.commit()
    return project.id


def send_and_read_back(collector: Collector, document: dict[str, Any]) -> Submission:
    """POST one envelope as its release wrote it, then find it again in the tenant's store."""
    response = collector.client.post("/findings", json=document, headers=bearer(collector.token))
    assert response.status_code == _OK, response.text
    assert response.json()["duplicate"] is False
    assert response.json()["stored"] == len(document["findings"])
    (record,) = collector.store.records(collector.scope)
    return record.submission


@pytest.fixture
def collector(database_url: str, monkeypatch: pytest.MonkeyPatch) -> Collector:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
    return serve(database_url, tenant(database_url), monkeypatch)


def test_the_corpus_holds_the_oldest_and_the_current_version() -> None:
    versions = {int(document["schema_version"]) for _, document in _ENVELOPES}

    assert min(SUPPORTED_SCHEMA_VERSIONS) in versions
    assert SCHEMA_VERSION in versions
    assert versions <= SUPPORTED_SCHEMA_VERSIONS


@pytest.mark.parametrize(
    "document", [document for _, document in _ENVELOPES], ids=[name for name, _ in _ENVELOPES]
)
def test_an_envelope_a_release_wrote_is_stored_as_it_was_sent(
    collector: Collector, document: dict[str, Any]
) -> None:
    stored = send_and_read_back(collector, document)

    assert stored.schema_version == document["schema_version"]
    assert stored == Submission.model_validate(document)


def test_an_agent_newer_than_its_collector_is_refused_with_the_versions_it_speaks(
    collector: Collector,
) -> None:
    """Collectors are upgraded before agents, and the refusal says so in its own words."""
    _, newest = _ENVELOPES[-1]
    future = {**newest, "schema_version": SCHEMA_VERSION + 1}

    response = collector.client.post("/findings", json=future, headers=bearer(collector.token))

    assert response.status_code == _UNPROCESSABLE
    assert str(sorted(SUPPORTED_SCHEMA_VERSIONS)) in response.json()["detail"]
    assert collector.store.records(collector.scope) == []
