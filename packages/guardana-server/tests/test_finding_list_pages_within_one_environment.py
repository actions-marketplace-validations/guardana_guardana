"""`finding list --environment` pages through that environment's findings only."""

import psycopg
from conftest import _clock, _submission
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import EvidenceIn, FindingIn
from guardana.server.lifecycle import list_tracked
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, create_organization, create_project


def _finding(path: str) -> FindingIn:
    return FindingIn(
        rule_id="guardana.supply_chain.pickle_opcode",
        severity="CRITICAL",
        title="Pickle runs code",
        target_ref=path,
        evidence=EvidenceIn(summary="os.system"),
        identity=f"identity-{path}",
    )


def _seeded(database_url: str) -> None:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web").id
    store = PostgresStore(database_url, clock=_clock)
    production = TenantScope.for_project(project, environment="production")
    dev = TenantScope.for_project(project, environment="dev")
    store.add(production, _submission(findings=[_finding("model/prod.pkl")]))
    store.add(dev, _submission(findings=[_finding("model/dev.pkl")]))


def test_control_without_a_limit_the_production_finding_is_listed(database_url: str) -> None:
    _seeded(database_url)

    with psycopg.connect(database_url) as connection:
        listed = list_tracked(connection, "acme/web", environment="production")

    assert "model/prod.pkl" in [entry.target_ref for entry in listed]


def test_a_one_row_page_for_production_holds_the_production_finding(database_url: str) -> None:
    _seeded(database_url)

    with psycopg.connect(database_url) as connection:
        listed = list_tracked(connection, "acme/web", environment="production", limit=1)

    assert [entry.target_ref for entry in listed] == ["model/prod.pkl"], listed
