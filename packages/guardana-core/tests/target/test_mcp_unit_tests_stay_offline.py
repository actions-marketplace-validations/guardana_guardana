"""No MCP unit test can reach a real resolver, and no MCP unit-test module can forget the guard.

A suite that resolves names passes on a laptop and fails on a runner without DNS, and a
lookup the code under test swallows reads as an unresolvable host rather than as a test
that reached the network.
"""

import ast
import socket
from pathlib import Path

import pytest
from _offline import refuse_name_lookups

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_PACKAGES = Path(__file__).resolve().parents[3]
_GUARDED = (
    *sorted((_PACKAGES / "guardana-core" / "tests" / "target").glob("test_mcp_*.py")),
    *sorted((_PACKAGES / "guardana-rules" / "tests" / "mcp").glob("test_*.py")),
)


def test_a_name_lookup_is_refused_and_remembered(request: pytest.FixtureRequest) -> None:
    attempted: list[str] = request.getfixturevalue("refuse_name_lookups")
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("mcp.example.test", 443)
    with pytest.raises(socket.gaierror):
        socket.gethostbyname("mcp.example.test")

    assert attempted == ["mcp.example.test", "mcp.example.test"]
    attempted.clear()


def test_an_address_literal_still_resolves_without_a_resolver() -> None:
    assert socket.getaddrinfo("127.0.0.1", 80)[0][4][0] == "127.0.0.1"
    assert socket.getaddrinfo("::1", 80)[0][4][0] == "::1"


def _imports_the_guard(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "_offline"
        and any(alias.name == "refuse_name_lookups" for alias in node.names)
        for node in tree.body
    )


def test_every_mcp_unit_test_module_imports_the_guard() -> None:
    assert len(_GUARDED) >= 20, "the glob found too few modules to be the MCP unit tests"
    unguarded = [
        str(path.relative_to(_PACKAGES)) for path in _GUARDED if not _imports_the_guard(path)
    ]

    assert not unguarded, f"these MCP unit-test modules may reach a resolver: {unguarded}"
