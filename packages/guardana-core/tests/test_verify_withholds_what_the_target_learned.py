"""A value the target learned during the run is withheld from what the run writes.

A server hands out a session id part-way through a run and may echo it into an error, so
the target's secrets are read again after the run, before `run.json` is written.
"""

import json
from dataclasses import replace

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_http import RawReply
from guardana.core.testing import ScriptedMcpServer
from guardana.core.verify import Verifier

_SESSION = "learned-session-7Q2mZp9XvR4tL8kNw3"


class _EchoesTheSession(ScriptedMcpServer):
    """A legacy server that answers `tools/list` with an error quoting the caller's session."""

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if not self.bodies or self.bodies[-1].get("method") != "tools/list":
            return reply
        error = {"code": -32000, "message": f"session {_SESSION} is not allowed to list tools"}
        return RawReply(200, {}, json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode())


def test_a_session_id_the_server_echoed_into_an_error_never_reaches_the_saved_run() -> None:
    server = _EchoesTheSession("https://93.184.215.14/mcp", session_ids=[_SESSION])
    target = McpServerTarget(server.url, sender=server, discovery_sender=server)
    base = default_profile()
    profile = replace(
        base, policy=replace(base.policy, include=("guardana.agent.mcp_server_manifest",))
    )

    verification = Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), profile=profile).run(
        target
    )

    assert [error.source for error in verification.result.errors] == [
        "guardana.agent.mcp_server_manifest"
    ]
    assert "is not allowed to list tools" in json.dumps(verification.document())
    assert _SESSION not in json.dumps(verification.document())
    assert _SESSION in target.sent_secrets()
