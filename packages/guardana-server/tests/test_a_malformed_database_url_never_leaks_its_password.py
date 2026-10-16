"""A connection string libpq cannot parse never carries its password into the error."""

import pytest
from guardana.server.db.connection import DatabaseUnreachableError, connect

_SYNTHETIC = "SYNTHETIC-COLLECTOR-PASSWORD"


def _said(url: str) -> str:
    try:
        connect(url)
    except DatabaseUnreachableError as exc:
        return str(exc)
    raise RuntimeError("precondition: the malformed URL should not connect")


def test_control_a_plain_password_in_a_malformed_url_is_masked() -> None:
    said = _said(f"postgresql://nobody:{_SYNTHETIC}@[::1/nothing")

    assert _SYNTHETIC not in said
    assert "***" in said


@pytest.mark.parametrize("cut", ["#", "?"])
def test_a_password_holding_a_url_delimiter_is_masked(cut: str) -> None:
    said = _said(f"postgresql://nobody:{_SYNTHETIC}{cut}tail@[::1/nothing")

    assert _SYNTHETIC not in said, said
