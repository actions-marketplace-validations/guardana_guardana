"""An stdio server's ref withholds credential values and keeps every other argument."""

import pytest
from _offline import refuse_name_lookups
from guardana.core.target.mcp import _stdio_ref

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_SERVER = ("python", "server.py")


@pytest.mark.parametrize(
    "flag", ["--keys-dir", "--author", "--sessions-dir", "--tokenizer", "--keyboard"]
)
def test_servers_that_differ_in_an_ordinary_flag_have_different_refs(flag: str) -> None:
    assert _stdio_ref((*_SERVER, flag, "a")) != _stdio_ref((*_SERVER, flag, "b"))


@pytest.mark.parametrize(
    "secret",
    [
        ("--token", "{}"),
        ("--api-key={}",),
        ("--authToken", "{}"),
        ("--accesstoken", "{}"),
        ("--client-secret", "{}"),
        ("API_KEY={}",),
        ("https://user:{}@mcp.example",),
    ],
)
def test_a_rotated_credential_keeps_the_ref_and_never_appears_in_it(
    secret: tuple[str, ...],
) -> None:
    old = _stdio_ref((*_SERVER, *(part.format("OLD-VALUE") for part in secret)))
    new = _stdio_ref((*_SERVER, *(part.format("NEW-VALUE") for part in secret)))

    assert old == new
    assert "VALUE" not in old


@pytest.mark.parametrize(
    "secret",
    [
        ("--header", "Authorization: Bearer {}"),
        ("--header=X-Api-Key: {}",),
        ("--env=GITHUB_TOKEN={}",),
        ("--env", "GITHUB_TOKEN={}"),
        ("--db=postgres://user:{}@db.example/app",),
        ("--pat", "{}"),
        ("--jwt", "{}"),
        ("--privatekey", "{}"),
        ("--passphrase", "{}"),
        ("--tokens", "{}"),
    ],
)
def test_a_credential_in_a_header_or_a_flags_value_is_withheld(secret: tuple[str, ...]) -> None:
    old = _stdio_ref((*_SERVER, *(part.format("OLD-VALUE") for part in secret)))
    new = _stdio_ref((*_SERVER, *(part.format("NEW-VALUE") for part in secret)))

    assert old == new


def test_an_ordinary_header_is_kept() -> None:
    plain = _stdio_ref((*_SERVER, "--header", "Accept: application/json"))
    other = _stdio_ref((*_SERVER, "--header", "Accept: text/plain"))

    assert plain != other
