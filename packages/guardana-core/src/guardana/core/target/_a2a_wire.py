"""The A2A v1 JSON-RPC binding, as far as an observer needs it: requests out, replies read.

Only reads are written here. Nothing in this module can spell `SendMessage`,
`CancelTask` or a push configuration, because a run that observes an agent must not
change anything the agent owns.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass

from guardana.core.target._mcp_http import RawReply

A2A_VERSION = "1.0"
"""The protocol version every request states, and the interface version a card must offer."""

TASK_NOT_FOUND = -32001
UNSUPPORTED_OPERATION = -32004
VERSION_NOT_SUPPORTED = -32009
METHOD_NOT_FOUND = -32601

_A2A_DEFINED = range(-32009, -32000)
"""The error codes the A2A specification defines, `-32009` to `-32001`."""


def a2a_defined(code: int | None) -> bool:
    """Whether `code` is one of the error codes the A2A specification defines."""
    return code is not None and code in _A2A_DEFINED


def request_body(method: str, params: Mapping[str, object], request_id: int) -> bytes:
    """Encode one JSON-RPC request."""
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
    return json.dumps(payload).encode("utf-8")


def request_headers(credential: str | None) -> dict[str, str]:
    """Return the headers every JSON-RPC request carries, with a bearer token when one is sent."""
    headers = {"Content-Type": "application/json", "A2A-Version": A2A_VERSION}
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    return headers


@dataclass(frozen=True, slots=True)
class RpcReply:
    """A JSON-RPC response object: a result, or an error with an integer code."""

    result: Mapping[str, object] | None
    code: int | None


def rpc_reply(reply: RawReply) -> RpcReply | None:
    """Read a JSON-RPC response object out of `reply`, or None when the body is not one.

    A result that is not an object is not one either: every A2A read answers with an
    object, and a bare value read as an empty one would turn a broken reply into an
    answer with nothing in it.
    """
    body = reply.json_object()
    if body is None:
        return None
    error = body.get("error")
    if isinstance(error, Mapping):
        code = error.get("code")
        if isinstance(code, int) and not isinstance(code, bool):
            return RpcReply(result=None, code=code)
        return None
    result = body.get("result")
    if isinstance(result, Mapping):
        return RpcReply(result=result, code=None)
    return None


def task_ids(result: Mapping[str, object]) -> tuple[str, ...]:
    """Return the non-empty string ids of the tasks a `ListTasks` result holds, in its order."""
    tasks = result.get("tasks")
    if not isinstance(tasks, list):
        return ()
    ids = (task.get("id") for task in tasks if isinstance(task, Mapping))
    return tuple(task_id for task_id in ids if isinstance(task_id, str) and task_id)


def listed_count(result: Mapping[str, object]) -> int | None:
    """How many task entries a `ListTasks` result holds, ids or not; None when `tasks` is no list.

    None is a result nobody can read as a listing: zero would turn it into an answered
    listing that showed nothing.
    """
    tasks = result.get("tasks")
    return len(tasks) if isinstance(tasks, list) else None


def continues(result: Mapping[str, object]) -> bool | None:
    """Whether a `ListTasks` result names a further page; None when its token is no string.

    An absent, null or empty `nextPageToken` is the last page.
    """
    token = result.get("nextPageToken")
    if token is None:
        return False
    return bool(token) if isinstance(token, str) else None


def total_size(result: Mapping[str, object]) -> int | None:
    """Return the `totalSize` a `ListTasks` result states, or None when it states no integer."""
    size = result.get("totalSize")
    return size if isinstance(size, int) and not isinstance(size, bool) else None
