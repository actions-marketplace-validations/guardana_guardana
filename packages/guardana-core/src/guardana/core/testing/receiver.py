"""A loopback HTTP receiver with one destination per delivery status a reporter reports.

An HTTP reporter's conformance needs a destination that accepts, one that answers and
refuses, and one that does not answer at all; this serves all three on `127.0.0.1`.
"""

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ACCEPTING_PATH = "/accept"
_REFUSING_PATH = "/refuse"
_ACCEPTED = 200
_REFUSED = 403
_ACKNOWLEDGEMENT = b'{"status":"ok","duplicate":false,"stored":0}'


@dataclass(frozen=True, slots=True)
class ReceivedRequest:
    """One request the receiver answered."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class Receiver:
    """The three destinations `receiver()` serves, and every request they answered."""

    accepting: str
    """Answers every request `200` with a collector's acknowledgement of one envelope."""

    refusing: str
    """Answers every request `403`."""

    closed: str
    """A loopback port nothing listens on, so a connection is refused."""

    received: list[ReceivedRequest] = field(default_factory=list)
    """Every request the accepting and refusing URLs answered, in order."""


@contextmanager
def receiver() -> Iterator[Receiver]:
    """Serve an accepting, a refusing and a closed URL on `127.0.0.1` for the block.

    Any method is answered, and a path past the accepting or refusing one is answered the
    same way, so a reporter may append its own. The server stops when the block ends.
    """
    received: list[ReceivedRequest] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _answer(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            with lock:
                received.append(
                    ReceivedRequest(
                        method=self.command,
                        path=self.path,
                        headers={key.lower(): value for key, value in self.headers.items()},
                        body=body,
                    )
                )
            accepted = self.path.startswith(_ACCEPTING_PATH)
            reply = _ACKNOWLEDGEMENT if accepted else b""
            self.send_response(_ACCEPTED if accepted else _REFUSED)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        do_POST = do_PUT = do_PATCH = do_GET = do_DELETE = _answer  # noqa: N815 — the names http.server dispatches to

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — the base signature
            """Stay quiet; a request log per delivery is noise in a test run."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    serving = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    try:
        closed_port = _unused_port()
        serving.start()
        port = server.server_address[1]
        yield Receiver(
            accepting=f"http://127.0.0.1:{port}{_ACCEPTING_PATH}",
            refusing=f"http://127.0.0.1:{port}{_REFUSING_PATH}",
            closed=f"http://127.0.0.1:{closed_port}/",
            received=received,
        )
    finally:
        if serving.is_alive():
            server.shutdown()
            serving.join()
        server.server_close()


def _unused_port() -> int:
    """Return a loopback port the system just handed out and nothing listens on.

    A socket bound and never listened on is no substitute: some systems drop a connection
    to it silently, so a reporter would wait out its timeout instead of being refused.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port
