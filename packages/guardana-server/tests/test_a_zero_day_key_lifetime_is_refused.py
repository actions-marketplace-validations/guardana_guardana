"""`key create --expires-in-days 0` never mints a key that lives until it is revoked."""

from datetime import datetime

import psycopg
import pytest
from guardana.server.auth import list_keys
from guardana.server.cli import EXIT_INVALID_USAGE, EXIT_OK, main


def _create(
    database_url: str, monkeypatch: pytest.MonkeyPatch, days: str
) -> tuple[int, list[datetime | None]]:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    main(["bootstrap", "--org", "acme", "--project", "web"])
    code = main(
        ["key", "create", "--project", "acme/web", "--name", "temporary", "--expires-in-days", days]
    )
    with psycopg.connect(database_url) as connection:
        expiries = [
            k.expires_at for k in list_keys(connection, project="acme/web") if k.name == "temporary"
        ]
    return code, expiries


def test_control_a_one_day_key_expires(database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    code, expiries = _create(database_url, monkeypatch, "1")

    assert code == EXIT_OK
    assert len(expiries) == 1
    assert expiries[0] is not None


@pytest.mark.parametrize("days", ["0", "-1"])
def test_a_zero_or_negative_lifetime_is_refused_and_nothing_is_stored(
    database_url: str, monkeypatch: pytest.MonkeyPatch, days: str
) -> None:
    assert _create(database_url, monkeypatch, days) == (EXIT_INVALID_USAGE, [])
