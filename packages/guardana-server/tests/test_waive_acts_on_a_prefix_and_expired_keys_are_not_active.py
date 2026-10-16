"""`finding waive` acts only on an identity prefix, and `key list` never calls a dead key active."""

from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from conftest import _submission
from guardana.server.auth import Scope, generate_key, store_key
from guardana.server.cli import EXIT_OK, main
from guardana.server.envelope import EvidenceIn, FindingIn
from guardana.server.lifecycle import list_tracked
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, resolve_project

_IDENTITY = "sha256:" + "4b8e2a6c" * 8


def _project(database_url: str, monkeypatch: pytest.MonkeyPatch) -> TenantScope:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    main(["bootstrap", "--org", "acme", "--project", "web"])
    with psycopg.connect(database_url) as connection:
        return TenantScope.for_project(resolve_project(connection, "acme/web").id)


def _waive(database_url: str, monkeypatch: pytest.MonkeyPatch, prefix: str) -> tuple[int, str]:
    scope = _project(database_url, monkeypatch)
    finding = FindingIn(
        rule_id="guardana.supply_chain.pickle_opcode",
        severity="CRITICAL",
        title="Pickle runs code",
        target_ref="model/a.pkl",
        evidence=EvidenceIn(summary="os.system"),
        identity=_IDENTITY,
    )
    PostgresStore(database_url).add(scope, _submission(findings=[finding]))
    code = main(
        [
            "finding",
            "waive",
            prefix,
            "--project",
            "acme/web",
            "--approver",
            "owner",
            "--reason",
            "accepted",
            "--expires",
            "2099-12-31",
        ]
    )
    with psycopg.connect(database_url) as connection:
        (tracked,) = list_tracked(connection, "acme/web")
    return code, tracked.status


def test_control_the_prefix_the_listing_prints_waives_the_finding(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _waive(database_url, monkeypatch, _IDENTITY[7:15]) == (EXIT_OK, "accepted_risk")


def test_control_a_prefix_matching_nothing_is_refused(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, status = _waive(database_url, monkeypatch, "ffffffff")

    assert (code != EXIT_OK, status) == (True, "open")


@pytest.mark.parametrize("prefix", ["%", "_", ""])
def test_a_wildcard_or_empty_prefix_waives_nothing(
    database_url: str, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    code, status = _waive(database_url, monkeypatch, prefix)

    assert (code != EXIT_OK, status) == (True, "open"), (code, status)


def _listed(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    expires_at: datetime,
) -> str:
    scope = _project(database_url, monkeypatch)
    issued, digest = generate_key("lapsing", (Scope.INGEST,))
    with psycopg.connect(database_url) as connection:
        store_key(connection, issued, digest, scope=scope, expires_at=expires_at)
        connection.commit()
    capsys.readouterr()
    main(["key", "list", "--project", "acme/web"])
    (line,) = [row for row in capsys.readouterr().out.splitlines() if row.endswith("lapsing")]
    return line


def test_control_a_key_still_within_its_lifetime_is_listed_active(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    line = _listed(database_url, monkeypatch, capsys, datetime.now(UTC) + timedelta(days=1))

    assert " active " in line


def test_an_expired_key_is_not_listed_active(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    line = _listed(database_url, monkeypatch, capsys, datetime.now(UTC) - timedelta(days=1))

    assert " active " not in line, line
