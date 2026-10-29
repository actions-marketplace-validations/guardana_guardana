"""A scripted A2A v1 agent, so an A2A rule gets its fixtures without a network.

It serves a card, answers the JSON-RPC reads per caller, keeps tasks per owner and
refuses the way a real agent's authentication layer does. Every knob is a behaviour
some deployed agent has: a card that declares security nobody enforces, tasks stored
under one shared owner, a method the agent does not offer.
"""

import json
from collections.abc import Collection, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from guardana.core.target._a2a_view import CARD_PATH
from guardana.core.target._mcp_http import DiscoveryScope, McpError, RawReply

_TASK_NOT_FOUND = -32001
_METHOD_NOT_FOUND = -32601
_READS = frozenset({"GetTask", "ListTasks", "GetExtendedAgentCard"})


def agent_card(
    interface_url: str, *, bearer: bool = True, extended: bool = False
) -> dict[str, Any]:
    """Build a complete A2A v1 card in the proto JSON the SDKs write.

    `bearer` declares one HTTP bearer scheme and requires it; `extended` declares
    that an extended card is served to `GetExtendedAgentCard`.
    """
    card: dict[str, Any] = {
        "name": "scripted-agent",
        "description": "Looks records up for the caller who asks.",
        "supportedInterfaces": [
            {"url": interface_url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "version": "1.0.0",
        "capabilities": {"extendedAgentCard": extended},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "lookup", "name": "Lookup", "description": "Look a record up."}],
    }
    if bearer:
        card["securitySchemes"] = {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}}
        card["securityRequirements"] = [{"schemes": {"bearer": {}}}]
    return card


class ScriptedA2aAgent:
    """An A2A agent double reached the way a real one is: through a sender.

    Pass an instance as `A2aAgentTarget(url, ..., sender=agent)` and every request the
    target would have put on the network arrives here instead.

    ```python
    agent = ScriptedA2aAgent(url, callers={"token-a": "alice", "token-b": "bob"},
                             tasks={"alice": ["task-1"]})
    target = A2aAgentTarget(url, credential="token-a", other_credential="token-b",
                            sender=agent)
    ```

    `callers` maps each bearer token to the owner it authenticates as. With `enforced`,
    a JSON-RPC request carrying no known token is answered `401`, except a method in
    `anonymous_methods`; without it, nobody is checked and every caller is anonymous
    (owner `""`). `tasks` maps an owner to the ids it holds; with `owner_bound` off,
    every caller sees every task. `errors` answers a method with a JSON-RPC error code,
    `statuses` answers a method (or `"card"`) with a bare HTTP status, and
    `silent_after` stops answering at all after that many requests.
    """

    def __init__(  # noqa: PLR0913 — one keyword per behaviour a real agent varies in
        self,
        url: str,
        *,
        card: Mapping[str, Any] | None = None,
        callers: Mapping[str, str] | None = None,
        enforced: bool = True,
        anonymous_methods: Collection[str] = (),
        tasks: Mapping[str, Sequence[str]] | None = None,
        owner_bound: bool = True,
        errors: Mapping[str, int] | None = None,
        statuses: Mapping[str, int] | None = None,
        silent_after: int | None = None,
    ) -> None:
        parts = urlsplit(url)
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.interface = f"{self.origin}/a2a"
        self.card = dict(card) if card is not None else agent_card(self.interface)
        self.callers = dict(callers or {})
        self.enforced = enforced
        self.anonymous_methods = frozenset(anonymous_methods)
        self.tasks = {owner: list(ids) for owner, ids in (tasks or {}).items()}
        self.owner_bound = owner_bound
        self.errors = dict(errors or {})
        self.statuses = dict(statuses or {})
        self.silent_after = silent_after
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        """Every request as it arrived: HTTP method, URL and headers."""

        self.calls: list[tuple[str, Mapping[str, Any], str | None]] = []
        """Every JSON-RPC call: its method, its params and the bearer token it carried."""

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        """Answer one request the way the configured agent would.

        `alongside` and `discovery` are accepted and ignored, so the signature is the
        one the `Sender` protocol publishes.
        """
        sent = dict(headers or {})
        self.requests.append((method, url, sent))
        if self.silent_after is not None and len(self.requests) > self.silent_after:
            raise McpError(f"could not reach {url}: the scripted agent stopped answering")
        if method == "GET":
            return self._card(url)
        if url != self.interface:
            return _status(404)
        request = json.loads((body or b"{}").decode("utf-8"))
        rpc_method = str(request.get("method"))
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        token = _bearer(sent.get("Authorization"))
        self.calls.append((rpc_method, params, token))
        if rpc_method in self.statuses:
            return _status(self.statuses[rpc_method])
        owner = self.callers.get(token) if token is not None else None
        if self.enforced and owner is None and rpc_method not in self.anonymous_methods:
            return _status(401)
        if rpc_method in self.errors:
            return _error(self.errors[rpc_method])
        return self._read(rpc_method, params, owner if self.enforced else "")

    def _card(self, url: str) -> RawReply:
        if "card" in self.statuses:
            return _status(self.statuses["card"])
        if urlsplit(url).path != CARD_PATH:
            return _status(404)
        return RawReply(200, {"Content-Type": "application/json"}, json.dumps(self.card).encode())

    def _read(self, method: str, params: Mapping[str, Any], owner: str | None) -> RawReply:
        if method not in _READS:
            return _error(_METHOD_NOT_FOUND)
        if method == "GetExtendedAgentCard":
            return _result({**self.card, "skills": [*self.card.get("skills", []), {"id": "x"}]})
        visible = self._visible(owner or "")
        if method == "ListTasks":
            size = params.get("pageSize")
            page = visible[: size if isinstance(size, int) else len(visible)]
            return _result(
                {"tasks": [_task(task_id) for task_id in page], "totalSize": len(visible)}
            )
        task_id = params.get("id")
        if task_id in visible:
            return _result(_task(str(task_id)))
        return _error(_TASK_NOT_FOUND)

    def _visible(self, owner: str) -> list[str]:
        if self.owner_bound:
            return list(self.tasks.get(owner, ()))
        return [task_id for ids in self.tasks.values() for task_id in ids]


def _bearer(header: str | None) -> str | None:
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    return token if scheme.lower() == "bearer" and token else None


def _task(task_id: str) -> dict[str, Any]:
    return {"id": task_id, "contextId": "ctx", "status": {"state": "TASK_STATE_COMPLETED"}}


def _result(result: Mapping[str, Any]) -> RawReply:
    payload = {"jsonrpc": "2.0", "id": 1, "result": dict(result)}
    return RawReply(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())


def _error(code: int) -> RawReply:
    payload = {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "scripted"}}
    return RawReply(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())


def _status(status: int) -> RawReply:
    return RawReply(status, {"Content-Type": "application/json"}, b'{"error": "scripted"}')


__all__ = ["ScriptedA2aAgent", "agent_card"]
