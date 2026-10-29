"""Serve an ASGI application built on a protocol SDK from a thread, on a loopback port."""

import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

_STARTUP_SECONDS = 10.0
_SHUTDOWN_SECONDS = 10.0


@dataclass(frozen=True)
class Seen:
    """One HTTP request a fixture server received, as the wire carried it."""

    method: str
    path: str
    host: str
    authorization: str | None


@dataclass
class Origin:
    """Where a fixture is served, handed to its factory before the application exists."""

    url: str
    seen: list[Seen] = field(default_factory=list)
    _server: uvicorn.Server | None = None

    def refuse_connections(self) -> None:
        """Close the listening socket, so every later connection attempt is refused.

        Call it from inside the application: the listeners belong to the server's loop.
        """
        if self._server is None:
            raise RuntimeError("the server has not started")
        for listener in self._server.servers:
            listener.close()


Factory = Callable[[Origin], ASGIApp]


class _Recorder:
    """Note every HTTP request before the application sees it."""

    def __init__(self, app: ASGIApp, origin: Origin) -> None:
        self._app = app
        self._origin = origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = {
                name.decode("latin-1"): value.decode("latin-1") for name, value in scope["headers"]
            }
            self._origin.seen.append(
                Seen(
                    scope["method"],
                    scope["path"],
                    headers.get("host", ""),
                    headers.get("authorization"),
                )
            )
        await self._app(scope, receive, send)


@contextmanager
def serving(factory: Factory) -> Iterator[Origin]:
    """Run the application `factory` builds on `127.0.0.1` and yield its origin.

    The port is bound before the application is built, so a factory can write its
    own URL into what it serves (protected-resource metadata, an agent card).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin = Origin(f"http://127.0.0.1:{port}")
    config = uvicorn.Config(
        _Recorder(factory(origin), origin),
        log_config=None,
        log_level="warning",
        access_log=False,
        lifespan="on",
        timeout_graceful_shutdown=1,
    )
    server = uvicorn.Server(config)
    origin._server = server
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        _wait_until_started(server, thread)
        yield origin
    finally:
        server.should_exit = True
        thread.join(_SHUTDOWN_SECONDS)
        sock.close()
    if thread.is_alive():
        raise RuntimeError(f"the fixture server at {origin.url} did not shut down")


def _wait_until_started(server: uvicorn.Server, thread: threading.Thread) -> None:
    """Block until uvicorn accepts connections; fail if its thread ended first."""
    deadline = time.monotonic() + _STARTUP_SECONDS
    while not server.started:
        if not thread.is_alive():
            raise RuntimeError("the fixture server stopped during startup")
        if time.monotonic() > deadline:
            raise RuntimeError("the fixture server did not start")
        time.sleep(0.01)
