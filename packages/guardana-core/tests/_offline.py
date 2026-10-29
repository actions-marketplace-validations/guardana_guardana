"""Keep a unit test away from real name resolution.

Import `refuse_name_lookups` into a test module and name it in
`pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)`: every test there then
runs with it, a name lookup fails as it would on a machine without a resolver, and the test
fails at teardown naming the host, so a lookup that the code under test swallowed still shows.
An IP literal resolves locally and passes. A test that scripts its own resolver
replaces this one for its duration.
"""

import ipaddress
import socket
from collections.abc import Iterator

import pytest


def _literal(host: object) -> bool:
    if host is None:
        return True
    name = host.decode() if isinstance(host, bytes) else str(host)
    try:
        ipaddress.ip_address(name.partition("%")[0])
    except ValueError:
        return False
    return True


@pytest.fixture(autouse=True)
def refuse_name_lookups(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Refuse every lookup of a name for one test, and fail the test if one was attempted."""
    real = socket.getaddrinfo
    attempted: list[str] = []

    def guarded(host: object, *args: object, **kwargs: object) -> object:
        if _literal(host):
            return real(host, *args, **kwargs)  # type: ignore[arg-type]
        attempted.append(str(host))
        raise socket.gaierror(socket.EAI_NONAME, f"a unit test may not look up {host!r}")

    def by_name(host: str) -> str:
        if _literal(host):
            return host
        attempted.append(host)
        raise socket.gaierror(socket.EAI_NONAME, f"a unit test may not look up {host!r}")

    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    monkeypatch.setattr(socket, "gethostbyname", by_name)
    yield attempted
    assert not attempted, f"a unit test looked up {attempted}; script the resolver instead"
