"""The label a probe sends to a collector never carries an stdio server's command line."""

import json
import shlex
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from _answering_collector import COLLECTOR_ACKNOWLEDGEMENT
from guardana.cli.main import app
from guardana.cli.probe import _mcp_source
from guardana.core.verify import Verification
from typer.testing import CliRunner

runner = CliRunner()

_SYNTHETIC = "audit-synthetic-token-0123456789"
_REF = "mcp+stdio://python#argv-0123456789abcdef"


def _verification() -> Verification:
    return cast(
        "Verification", SimpleNamespace(manifest=SimpleNamespace(target=SimpleNamespace(ref=_REF)))
    )


def test_a_command_is_named_by_the_targets_ref() -> None:
    source = _mcp_source(f"python server.py --token {_SYNTHETIC}", _verification())

    assert source == _REF
    assert _SYNTHETIC not in source


def test_a_url_is_shown_without_its_secrets() -> None:
    source = _mcp_source(f"https://user:{_SYNTHETIC}@mcp.invalid/mcp", _verification())

    assert _SYNTHETIC not in source
    assert source.startswith("https://mcp.invalid/")


_STDIO_SERVER = """
import json, sys
for line in sys.stdin:
    asked = json.loads(line)
    if "id" not in asked:
        continue
    if asked.get("method") == "initialize":
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
    elif asked.get("method") == "tools/list":
        result = {"tools": [{"name": "lookup", "description": "Look a record up by its key."}]}
    else:
        result = None
    reply = {"jsonrpc": "2.0", "id": asked["id"]}
    reply.update({"result": result} if result is not None else
                 {"error": {"code": -32601, "message": "Method not found"}})
    sys.stdout.write(json.dumps(reply) + "\\n")
    sys.stdout.flush()
"""


@contextmanager
def _collector() -> Iterator[tuple[str, list[dict[str, object]]]]:
    """Serve on loopback, keeping every envelope posted to it."""
    received: list[dict[str, object]] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(COLLECTOR_ACKNOWLEDGEMENT)))
            self.end_headers()
            self.wfile.write(COLLECTOR_ACKNOWLEDGEMENT)

        def log_message(self, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", received
    finally:
        server.shutdown()
        server.server_close()


def test_a_probed_stdio_command_reaches_the_collector_without_its_arguments(
    tmp_path: Path,
) -> None:
    script = tmp_path / "server.py"
    script.write_text(_STDIO_SERVER, encoding="utf-8")
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(script))} --token {_SYNTHETIC}"

    with _collector() as (url, received):
        result = runner.invoke(
            app, ["probe", "--mcp", command, "--allow-exec", "--reporter", f"server://{url}"]
        )

    assert [envelope["source"] for envelope in received], result.output
    (envelope,) = received
    assert _SYNTHETIC not in json.dumps(envelope)
    assert str(envelope["source"]).startswith("mcp+stdio://")
