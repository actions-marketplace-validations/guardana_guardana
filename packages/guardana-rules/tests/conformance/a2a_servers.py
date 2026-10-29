"""A2A v1 agents built on the `a2a-sdk`, one factory per row of the conformance fixture table.

The agent card route, the JSON-RPC binding, the task store and the error codes are the
SDK's. Each factory writes only the policy its row is about: which card it publishes,
whether Starlette's `AuthenticationMiddleware` guards the JSON-RPC route, whose name a
task is stored under, and which handler method refuses.
"""

import asyncio
import json
from collections.abc import Callable

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.routes.common import StarletteUser
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import a2a_pb2
from a2a.utils.errors import UnsupportedOperationError
from sdk_harness import Origin
from starlette.applications import Starlette
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Route, request_response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

RPC_PATH = "/a2a"
CARD_PATH = "/.well-known/agent-card.json"
CREDENTIAL_A = "conformance-caller-a-token"
CREDENTIAL_B = "conformance-caller-b-token"
OWNER_A = "caller-a"
OWNER_B = "caller-b"
TASK_A = "0b7e5d2c-91f4-4a6e-8c3d-5f2a1e9b7c40"
"""The one task stored, owned by caller A."""
SCHEME = "bearer"
UNDECLARED_SCHEME = "partner-mtls"
SHARED_OWNER = "everyone"

_CALLERS = {CREDENTIAL_A: OWNER_A, CREDENTIAL_B: OWNER_B}


class _Bearer(AuthenticationBackend):
    """Map each conformance token to its caller; anything else is refused."""

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, SimpleUser]:
        """Return the caller a bearer token names, or raise so the middleware answers `401`."""
        scheme, _, token = conn.headers.get("authorization", "").partition(" ")
        owner = _CALLERS.get(token) if scheme.lower() == "bearer" else None
        if owner is None:
            raise AuthenticationError("a bearer token this agent issued is required")
        return AuthCredentials(["authenticated"]), SimpleUser(owner)


def _unauthorized(conn: HTTPConnection, exc: AuthenticationError) -> Response:
    return JSONResponse(
        {"error": str(exc)}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
    )


class _Idle(AgentExecutor):
    """An agent that does nothing: no conformance check sends it a message."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Publish nothing."""

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel nothing."""


class _WithoutListTasks(DefaultRequestHandler):
    """A handler that does not offer `ListTasks`."""

    async def on_list_tasks(
        self, params: a2a_pb2.ListTasksRequest, context: ServerCallContext
    ) -> a2a_pb2.ListTasksResponse:
        """Refuse, as an agent without task listing does."""
        raise UnsupportedOperationError


class _MethodGate:
    """Let one JSON-RPC method past the authentication middleware; guard every other."""

    def __init__(self, guarded: ASGIApp, anonymous: ASGIApp, method: str) -> None:
        self._guarded = guarded
        self._anonymous = anonymous
        self._method = method

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        messages: list[Message] = []
        more = True
        while more:
            message = await receive()
            messages.append(message)
            more = message.get("more_body", False)
        body = b"".join(m.get("body", b"") for m in messages)
        try:
            method = json.loads(body).get("method")
        except (ValueError, AttributeError):
            method = None
        pending = iter(messages)

        async def replay() -> Message:
            return next(pending, None) or await receive()

        target = self._anonymous if method == self._method else self._guarded
        await target(scope, replay, send)


def _card(
    origin: Origin,
    *,
    security: bool = True,
    extended: bool = False,
    interface_url: str | None = None,
) -> a2a_pb2.AgentCard:
    card = a2a_pb2.AgentCard(
        name="conformance-agent",
        description="Looks records up for the caller who asks.",
        version="1.0.0",
        supported_interfaces=[
            a2a_pb2.AgentInterface(
                url=interface_url or f"{origin.url}{RPC_PATH}",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=a2a_pb2.AgentCapabilities(extended_agent_card=extended),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[
            a2a_pb2.AgentSkill(
                id="lookup",
                name="Lookup",
                description="Look a record up by its key.",
                tags=["records"],
            )
        ],
    )
    if security:
        card.security_schemes[SCHEME].http_auth_security_scheme.scheme = "Bearer"
        card.security_requirements.add().schemes[SCHEME].SetInParent()
    return card


def _extended(card: a2a_pb2.AgentCard) -> a2a_pb2.AgentCard:
    extended = a2a_pb2.AgentCard()
    extended.CopyFrom(card)
    extended.skills.add(
        id="audit", name="Audit", description="Read the audit trail.", tags=["audit"]
    )
    return extended


def _store(owner: Callable[[ServerCallContext], str] | None = None) -> InMemoryTaskStore:
    """A task store holding `TASK_A` under the name caller A's token authenticates as."""
    store = InMemoryTaskStore() if owner is None else InMemoryTaskStore(owner_resolver=owner)
    task = a2a_pb2.Task(
        id=TASK_A,
        context_id="conformance-context",
        status=a2a_pb2.TaskStatus(state=a2a_pb2.TaskState.TASK_STATE_COMPLETED),
    )
    asyncio.run(store.save(task, ServerCallContext(user=StarletteUser(SimpleUser(OWNER_A)))))
    return store


def _agent(
    card: a2a_pb2.AgentCard,
    *,
    enforced: bool = True,
    store: InMemoryTaskStore | None = None,
    handler_class: type[DefaultRequestHandler] = DefaultRequestHandler,
    anonymous_method: str | None = None,
) -> ASGIApp:
    """Serve `card` and its JSON-RPC binding, guarding only the JSON-RPC route when enforced."""
    handler = handler_class(
        agent_executor=_Idle(),
        task_store=store or _store(),
        agent_card=card,
        extended_agent_card=_extended(card) if card.capabilities.extended_agent_card else None,
    )
    routes: list[BaseRoute] = [*create_agent_card_routes(card, card_url=CARD_PATH)]
    for route in create_jsonrpc_routes(handler, RPC_PATH):
        if not enforced or not isinstance(route, Route):
            routes.append(route)
            continue
        endpoint = request_response(route.endpoint)
        guarded: ASGIApp = AuthenticationMiddleware(
            endpoint, backend=_Bearer(), on_error=_unauthorized
        )
        if anonymous_method is not None:
            guarded = _MethodGate(guarded, endpoint, anonymous_method)
        routes.append(Route(route.path, guarded, methods=["POST"]))
    return Starlette(routes=routes)


def owner_bound(origin: Origin) -> ASGIApp:
    """Bearer required and enforced, tasks keyed by owner, one task stored for caller A."""
    return _agent(_card(origin, extended=True))


def security_unenforced(origin: Origin) -> ASGIApp:
    """The card requires a bearer token; nothing checks one."""
    return _agent(_card(origin), enforced=False)


def no_security(origin: Origin) -> ASGIApp:
    """The card declares no security and nothing checks a credential."""
    return _agent(_card(origin, security=False), enforced=False)


def constant_owner(origin: Origin) -> ASGIApp:
    """Bearer enforced, but every task is stored and looked up under one shared owner."""
    return _agent(_card(origin), store=_store(lambda context: SHARED_OWNER))


def extended_card_anonymous(origin: Origin) -> ASGIApp:
    """Bearer enforced on every method except `GetExtendedAgentCard`."""
    return _agent(_card(origin, extended=True), anonymous_method="GetExtendedAgentCard")


def _default_account(context: ServerCallContext) -> str:
    """Resolve an unauthenticated request to the account that owns the stored task."""
    return context.user.user_name if context.user.is_authenticated else OWNER_A


def get_task_unguarded(origin: Origin) -> ASGIApp:
    """Bearer enforced on every method except `GetTask`, which sees every caller as caller A."""
    return _agent(_card(origin), store=_store(_default_account), anonymous_method="GetTask")


def no_list_tasks(origin: Origin) -> ASGIApp:
    """Bearer enforced; `ListTasks` answered as an unsupported operation."""
    return _agent(_card(origin), handler_class=_WithoutListTasks)


def card_defects(origin: Origin) -> ASGIApp:
    """A card with no description whose security requirement names an undeclared scheme."""
    card = _card(origin)
    card.ClearField("description")
    del card.security_requirements[:]
    card.security_requirements.add().schemes[UNDECLARED_SCHEME].SetInParent()
    return _agent(card)


def other_origin(origin: Origin) -> str:
    """The origin the interface-elsewhere card points at: this server, named another way."""
    return origin.url.replace("127.0.0.1", "localhost")


def interface_elsewhere(origin: Origin) -> ASGIApp:
    """Bearer enforced; the card's JSON-RPC interface is on another origin."""
    return _agent(_card(origin, interface_url=f"{other_origin(origin)}{RPC_PATH}"))
