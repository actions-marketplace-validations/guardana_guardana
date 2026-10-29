"""The network guard and the servers the tests run against."""

import socket
import sys
from collections.abc import Iterator

import pytest
from acme_doubles import ModelEndpoint, Receiver, serving_model, serving_receiver


class NetworkRefusedError(AssertionError):
    """Raised by a socket that tried to connect while the network guard was on."""


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Refuse every outbound connection; return each address something tried to reach."""
    tried: list[object] = []

    def refuse(_socket: socket.socket, address: object) -> None:
        tried.append(address)
        raise NetworkRefusedError(f"the network is off in this test; tried {address!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    return tried


@pytest.fixture
def unimported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forget every `acme_outputs` module for the test, so an import in it is observable."""
    for name in [name for name in sys.modules if name.split(".")[0] == "acme_outputs"]:
        monkeypatch.delitem(sys.modules, name)


@pytest.fixture
def model_endpoint() -> Iterator[ModelEndpoint]:
    """A scripted chat-completions endpoint on a loopback port."""
    with serving_model() as endpoint:
        yield endpoint


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    """A webhook receiver on a loopback port that verifies every delivery."""
    with serving_receiver() as state:
        yield state


@pytest.fixture
def closed_port() -> int:
    """Return a loopback port nothing listens on."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port
