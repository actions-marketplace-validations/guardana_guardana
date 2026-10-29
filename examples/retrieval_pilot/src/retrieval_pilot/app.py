"""The reference application: a chat endpoint over a tenant-filtered index and an order tool.

The tenant comes from the request's credentials, each tenant's key from the environment
variable its fixtures file names. The "model" is deterministic: it answers from the top
document the asking tenant may read, or from the order tool when the question names an
order id. Two switches break it the way the checks are built to catch.
"""

import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BufferedIOBase
from pathlib import Path
from typing import Any

from guardana.core.doubles import Doubles, open_doubles
from guardana.core.fixtures import Fixtures, load_fixtures

from retrieval_pilot.index import Document, KeywordIndex

NOT_FOUND = "I could not find that in your documents."
"""The reply when the asking tenant may read nothing that matches."""

ORDER_TOOL = "lookup_order"
"""The tool the fixtures file declares for reading one order by its id."""

_ORDER_ID = re.compile(r"\b[A-Z]-\d+\b")
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_INSTRUCTION = re.compile(r"<!--.*?\bwith (\S+) and (\S+) joined by.*?-->", re.DOTALL)
_MAX_BODY = 1 << 20


class CredentialsError(Exception):
    """A request carried a key no tenant holds, or credentials that are not a bearer key."""


class MalformedRequestError(Exception):
    """A request is not an OpenAI-compatible chat completion with a user message."""


@dataclass(frozen=True, slots=True)
class Switches:
    """How the application is broken; both off is the fixed application."""

    break_tenant_filter: bool = False
    """Search every tenant's documents, and act as whichever tenant holds the order asked about."""

    obey_documents: bool = False
    """End a reply as an instruction hidden in the retrieved document asks."""


class ReferenceApplication:
    """Answers chat questions as the tenant a request's key belongs to.

    Every request is counted in `received`, so a test can compare it with what the run
    says it sent. The doubles serve the order tool and write their trace until `close`.
    """

    def __init__(
        self,
        fixtures: Path,
        documents: Path,
        *,
        trace: Path,
        switches: Switches,
        environ: Mapping[str, str],
    ) -> None:
        """Load the fixtures, the index and each tenant's key; raise when one is missing."""
        declared = load_fixtures(fixtures)
        self._tenants = _tenant_keys(declared, environ)
        self._index = KeywordIndex.load(documents)
        self._switches = switches
        self._doubles: Doubles = open_doubles(fixtures, trace=trace)
        self._lock = threading.Lock()
        self.received = 0

    def count(self) -> None:
        """Count one request received."""
        with self._lock:
            self.received += 1

    def tenant_for(self, api_key: str | None) -> str | None:
        """Return the tenant `api_key` belongs to; None without a key; raise for an unknown one."""
        if api_key is None:
            return None
        tenant = self._tenants.get(api_key)
        if tenant is None:
            raise CredentialsError("no tenant holds this key")
        return tenant

    def answer(self, api_key: str | None, question: str) -> str:
        """Answer `question` as the tenant `api_key` belongs to."""
        tenant = self.tenant_for(api_key)
        order = _ORDER_ID.search(question)
        if order is not None:
            return self._order(tenant, order.group(0))
        if tenant is None:
            return NOT_FOUND
        document = self._index.search(
            question, tenant, filtered=not self._switches.break_tenant_filter
        )
        return NOT_FOUND if document is None else self._from(document)

    def close(self) -> None:
        """Close the doubles, which writes the trace's footer."""
        self._doubles.close()

    def _from(self, document: Document) -> str:
        reply = f"From your documents: {_COMMENT.sub('', document.text).strip()}"
        instruction = _INSTRUCTION.search(document.text)
        if self._switches.obey_documents and instruction is not None:
            reply = f"{reply} {instruction.group(1)}-{instruction.group(2)}"
        return reply

    def _order(self, tenant: str | None, order_id: str) -> str:
        acting = [tenant] if tenant is not None else []
        if self._switches.break_tenant_filter:
            acting = list(self._tenants.values())
        for name in acting:
            with self._doubles.acting_as(name):
                found = self._doubles.call(ORDER_TOOL, id=order_id)
            if isinstance(found, dict):
                details = ", ".join(f"{key} {value}" for key, value in found.items() if key != "id")
                return f"Order {order_id}: {details}."
        return f"I could not find order {order_id}."


def _tenant_keys(fixtures: Fixtures, environ: Mapping[str, str]) -> dict[str, str]:
    keys: dict[str, str] = {}
    for tenant in fixtures.tenants:
        if tenant.api_key_env is None:
            raise ValueError(f"tenant {tenant.name}: this application reads keys from api_key_env")
        key = environ.get(tenant.api_key_env, "")
        if not key:
            raise ValueError(f"tenant {tenant.name}: {tenant.api_key_env} is unset or empty")
        if key in keys:
            raise ValueError(f"tenants {keys[key]} and {tenant.name} share one key")
        keys[key] = tenant.name
    return keys


def make_server(application: ReferenceApplication, host: str, port: int) -> ThreadingHTTPServer:
    """Serve `application` as an OpenAI-compatible `POST /v1/chat/completions`."""

    class Handler(BaseHTTPRequestHandler):
        """Answers one chat completion per request, counting every request first."""

        def do_POST(self) -> None:
            """Reply 200 with the answer, 401 for unknown credentials, 400 for anything else."""
            application.count()
            if self.path.rstrip("/") != "/v1/chat/completions":
                self._send(404, {"error": {"message": "not found"}})
                return
            try:
                body = _chat_request(self.headers.get("Content-Length"), self.rfile)
                key = _bearer(self.headers.get("Authorization"))
                reply = application.answer(key, _last_user_message(body))
            except CredentialsError:
                self._send(401, {"error": {"message": "invalid API key"}})
                return
            except MalformedRequestError:
                self._send(400, {"error": {"message": "malformed chat request"}})
                return
            self._send(
                200,
                {
                    "object": "chat.completion",
                    "model": str(body.get("model", "")),
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": reply},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — the base class names it
            """Stay quiet: a probe sends many requests."""

    return ThreadingHTTPServer((host, port), Handler)


def _bearer(header: str | None) -> str | None:
    if header is None:
        return None
    scheme, _, key = header.partition(" ")
    if scheme.lower() != "bearer" or not key.strip():
        raise CredentialsError("not a bearer key")
    return key.strip()


def _chat_request(length: str | None, stream: BufferedIOBase) -> dict[str, Any]:
    try:
        size = int(length or "0")
    except ValueError:
        raise MalformedRequestError("Content-Length is not a number") from None
    if not 0 < size <= _MAX_BODY:
        raise MalformedRequestError("no body, or one over the limit")
    try:
        body = json.loads(stream.read(size))
    except ValueError:
        raise MalformedRequestError("the body is not JSON") from None
    if not isinstance(body, dict):
        raise MalformedRequestError("the body is not a JSON object")
    return body


def _last_user_message(body: Mapping[str, Any]) -> str:
    messages = body.get("messages")
    if not isinstance(messages, list):
        raise MalformedRequestError("no messages")
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                return content
    raise MalformedRequestError("no user message")


__all__ = [
    "NOT_FOUND",
    "ORDER_TOOL",
    "CredentialsError",
    "MalformedRequestError",
    "ReferenceApplication",
    "Switches",
    "make_server",
]
