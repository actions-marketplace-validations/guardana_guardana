"""A loopback server that answers every POST with one scripted status and body.

Real sockets, so the reporter's own transport reads the answer: whether a reply counts
as a collector's acknowledgement is decided by the bytes urllib returns, which a double
of the transport would skip.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COLLECTOR_ACKNOWLEDGEMENT = b'{"status": "ok", "duplicate": false, "stored": 0}'
"""What every collector release answers to an envelope it accepted."""


@dataclass
class Answering:
    """Where the server listens, and the path of every POST it answered."""

    url: str
    heard: list[str] = field(default_factory=list)


@contextmanager
def answering(status: int, body: bytes) -> Iterator[Answering]:
    """Serve on `127.0.0.1`, answering each POST with `status` and `body`."""
    heard: list[str] = []

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            """Stay quiet."""

        def do_POST(self) -> None:
            """Read the envelope and answer as scripted."""
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            heard.append(self.path)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Answering(f"http://127.0.0.1:{server.server_address[1]}", heard)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
