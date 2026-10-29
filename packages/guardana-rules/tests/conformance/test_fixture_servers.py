"""Each SDK-built fixture behaves on the wire the way its row of the fixture table says.

Plain `urllib` JSON-RPC, no Guardana target: if a fixture drifts, the conformance tests
built on it would grade the wrong server, so its behaviour is pinned first.
"""

import json
import socket
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import a2a_servers as a2a
import mcp_servers as mcp
import pytest
from sdk_harness import Factory, Origin, serving

MODERN = "2026-07-28"
_ENVELOPE = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "conformance-test", "version": "1"},
}
_TIMEOUT = 5


@dataclass(frozen=True)
class Reply:
    """One HTTP answer, its JSON-RPC body decoded whether it came as JSON or as one SSE event."""

    status: int
    headers: dict[str, str]
    body: dict[str, Any]

    @property
    def result(self) -> dict[str, Any]:
        """The JSON-RPC result; fails the test when the server answered an error."""
        assert "result" in self.body, self.body
        result: dict[str, Any] = self.body["result"]
        return result

    @property
    def error(self) -> dict[str, Any]:
        """The JSON-RPC error; fails the test when the server answered a result."""
        assert "error" in self.body, self.body
        error: dict[str, Any] = self.body["error"]
        return error


def _decode(raw: bytes, content_type: str) -> dict[str, Any]:
    text = raw.decode()
    if content_type.startswith("text/event-stream"):
        text = next(line[len("data:") :] for line in text.splitlines() if line.startswith("data:"))
    decoded: dict[str, Any] = json.loads(text) if text.strip() else {}
    return decoded


def _post(url: str, method: str, params: dict[str, Any], headers: dict[str, str]) -> Reply:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(  # noqa: S310 - a loopback fixture URL
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **headers,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as answer:  # noqa: S310
            return Reply(
                answer.status,
                dict(answer.headers),
                _decode(answer.read(), answer.headers.get("content-type", "")),
            )
    except urllib.error.HTTPError as refused:
        with refused:
            return Reply(
                refused.code,
                dict(refused.headers),
                _decode(refused.read(), refused.headers.get("content-type", "")),
            )


def _get(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as answer:  # noqa: S310
        document: dict[str, Any] = json.loads(answer.read())
        return document


def _bearer(credential: str | None) -> dict[str, str]:
    return {} if credential is None else {"Authorization": f"Bearer {credential}"}


def _modern(
    origin: Origin, method: str, credential: str | None = mcp.CREDENTIAL, **params: object
) -> Reply:
    headers = {"MCP-Protocol-Version": MODERN, "Mcp-Method": method, **_bearer(credential)}
    return _post(f"{origin.url}{mcp.MCP_PATH}", method, {"_meta": _ENVELOPE, **params}, headers)


def _initialize(origin: Origin, credential: str | None = mcp.CREDENTIAL) -> Reply:
    params = {
        "protocolVersion": mcp.LEGACY_REVISION,
        "capabilities": {},
        "clientInfo": {"name": "conformance-test", "version": "1"},
    }
    return _post(f"{origin.url}{mcp.MCP_PATH}", "initialize", params, _bearer(credential))


@dataclass(frozen=True)
class Session:
    """A `2025-11-25` session opened by `initialize` and `notifications/initialized`."""

    origin: Origin
    opening: dict[str, Any]
    session_id: str
    credential: str | None

    def call(self, method: str, **params: object) -> Reply:
        """Send one request inside the session."""
        headers = {
            "Mcp-Session-Id": self.session_id,
            "MCP-Protocol-Version": mcp.LEGACY_REVISION,
            **_bearer(self.credential),
        }
        return _post(f"{self.origin.url}{mcp.MCP_PATH}", method, params, headers)


def _session(origin: Origin, credential: str | None = mcp.CREDENTIAL) -> Session:
    opened = _initialize(origin, credential)
    session_id = opened.headers.get("mcp-session-id")
    assert opened.status == 200
    assert session_id is not None
    notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    request = urllib.request.Request(  # noqa: S310
        f"{origin.url}{mcp.MCP_PATH}",
        data=notification,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Session-Id": session_id,
            "MCP-Protocol-Version": mcp.LEGACY_REVISION,
            **_bearer(credential),
        },
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as answer:  # noqa: S310
        assert answer.status == 202
    return Session(origin, opened.result, session_id, credential)


@pytest.fixture
def origin(request: pytest.FixtureRequest) -> Iterator[Origin]:
    factory: Factory = request.param
    with serving(factory) as served:
        yield served


def test_the_harness_stops_listening_once_the_block_ends() -> None:
    with serving(mcp.open_server) as served:
        assert _modern(served, "server/discover", credential=None).status == 200
        port = urlsplit(served.url).port
    assert port is not None
    with (
        pytest.raises(ConnectionRefusedError),
        socket.create_connection(("127.0.0.1", port), timeout=_TIMEOUT),
    ):
        pass


# --- MCP ---------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", [mcp.legacy_only_gated], indirect=True)
def test_a_legacy_only_server_answers_the_handshake_and_refuses_discovery(origin: Origin) -> None:
    session = _session(origin)

    assert session.opening["protocolVersion"] == mcp.LEGACY_REVISION
    assert session.call("tools/list").result["tools"][0]["name"] == mcp.TOOL
    assert _modern(origin, "server/discover").error["code"] == -32601


@pytest.mark.parametrize("origin", [mcp.modern_only_gated], indirect=True)
def test_a_modern_only_server_answers_discovery_and_refuses_the_handshake(origin: Origin) -> None:
    assert _modern(origin, "server/discover").result["supportedVersions"] == [MODERN]
    assert _modern(origin, "tools/list").result["tools"][0]["name"] == mcp.TOOL

    refused = _initialize(origin).error
    assert refused["code"] == -32022
    assert refused["data"]["supported"] == [MODERN]


@pytest.mark.parametrize("origin", [mcp.dual_era_gated], indirect=True)
def test_a_dual_era_server_lists_only_the_modern_revision_and_still_answers_the_handshake(
    origin: Origin,
) -> None:
    assert _modern(origin, "server/discover").result["supportedVersions"] == [MODERN]
    assert _modern(origin, "tools/list").result["tools"][0]["name"] == mcp.TOOL

    session = _session(origin)
    assert session.opening["protocolVersion"] == mcp.LEGACY_REVISION
    assert session.call("tools/list").result["tools"][0]["name"] == mcp.TOOL


@pytest.mark.parametrize(
    "origin", [mcp.legacy_only_gated, mcp.modern_only_gated, mcp.dual_era_gated], indirect=True
)
@pytest.mark.parametrize("credential", [None, "a-token-nobody-issued"])
def test_a_gated_server_refuses_a_request_without_its_token(
    origin: Origin, credential: str | None
) -> None:
    refused = _initialize(origin, credential)

    assert refused.status == 401
    assert _modern(origin, "server/discover", credential=credential).status == 401
    resource_metadata = f"{origin.url}/.well-known/oauth-protected-resource{mcp.MCP_PATH}"
    assert f'resource_metadata="{resource_metadata}"' in refused.headers["www-authenticate"]


@pytest.mark.parametrize("origin", [mcp.open_server], indirect=True)
def test_an_open_server_answers_both_revisions_without_a_credential(origin: Origin) -> None:
    assert _modern(origin, "tools/list", credential=None).result["tools"][0]["name"] == mcp.TOOL
    assert (
        _session(origin, credential=None).call("tools/list").result["tools"][0]["name"] == mcp.TOOL
    )


@pytest.mark.parametrize("origin", [mcp.accepting_any_token], indirect=True)
def test_a_server_accepting_any_token_answers_one_it_never_issued(origin: Origin) -> None:
    listed = _modern(origin, "tools/list", credential="a-token-nobody-issued")

    assert listed.result["tools"][0]["name"] == mcp.TOOL
    assert _modern(origin, "tools/list", credential=None).status == 401


@pytest.mark.parametrize(
    "origin", [mcp.modern_public_cache, mcp.dual_era_public_cache], indirect=True
)
def test_a_public_cache_hint_reaches_the_modern_tool_listing(origin: Origin) -> None:
    assert _modern(origin, "tools/list").result["cacheScope"] == "public"


@pytest.mark.parametrize("origin", [mcp.dual_era_gated], indirect=True)
def test_without_the_hint_the_modern_tool_listing_is_private(origin: Origin) -> None:
    assert _modern(origin, "tools/list").result["cacheScope"] == "private"


@pytest.mark.parametrize("origin", [mcp.legacy_public_cache], indirect=True)
def test_the_legacy_revision_carries_no_cache_scope_for_the_same_hint(origin: Origin) -> None:
    listed = _session(origin).call("tools/list").result

    assert listed["tools"][0]["name"] == mcp.TOOL
    assert "cacheScope" not in listed
    assert _modern(origin, "server/discover").error["code"] == -32601


@pytest.mark.parametrize("origin", [mcp.legacy_tasks_owner_bound], indirect=True)
def test_an_owner_bound_task_listing_shows_the_operator_only_its_own_task(origin: Origin) -> None:
    session = _session(origin)

    assert "list" in session.opening["capabilities"]["tasks"]
    listed = session.call("tasks/list").result["tasks"]
    assert [task["taskId"] for task in listed] == [mcp.OWNED_TASK]
    assert _initialize(origin, credential=None).status == 401


@pytest.mark.parametrize("origin", [mcp.legacy_tasks_listed_to_anyone], indirect=True)
def test_an_open_task_listing_shows_a_caller_without_a_credential_counting_ids(
    origin: Origin,
) -> None:
    session = _session(origin, credential=None)

    assert "list" in session.opening["capabilities"]["tasks"]
    listed = session.call("tasks/list").result["tasks"]
    assert [task["taskId"] for task in listed] == list(mcp.COUNTING_TASKS)


@pytest.mark.parametrize("origin", [mcp.legacy_tasks_none_stored], indirect=True)
def test_an_open_task_listing_with_no_task_stored_answers_an_empty_list(origin: Origin) -> None:
    session = _session(origin, credential=None)

    assert "list" in session.opening["capabilities"]["tasks"]
    assert session.call("tasks/list").result["tasks"] == []


@pytest.mark.parametrize("origin", [mcp.dual_era_gated], indirect=True)
def test_a_server_without_tasks_declares_none_and_answers_tasks_list_as_unknown(
    origin: Origin,
) -> None:
    session = _session(origin)

    assert "tasks" not in session.opening["capabilities"]
    assert session.call("tasks/list").error["code"] == -32601


@pytest.mark.parametrize("origin", [mcp.modern_tasks_extension], indirect=True)
def test_the_modern_tasks_extension_is_declared_and_tasks_list_is_unknown(origin: Origin) -> None:
    discovered = _modern(origin, "server/discover", credential=None).result

    assert mcp.TASKS_EXTENSION in discovered["capabilities"]["extensions"]
    unknown = _modern(origin, "tasks/list", credential=None)
    assert unknown.status == 404
    assert unknown.error["code"] == -32601


def _authorization_documents(origin: Origin) -> tuple[str, str, dict[str, Any]]:
    """The protected resource's first authorization server, the URL built from it, its document."""
    resource = _get(f"{origin.url}/.well-known/oauth-protected-resource{mcp.MCP_PATH}")
    named: str = resource["authorization_servers"][0]
    parts = urlsplit(named)
    well_known = f"{parts.scheme}://{parts.netloc}{mcp.AUTHORIZATION_SERVER_METADATA}{parts.path}"
    return named, well_known, _get(well_known)


@pytest.mark.parametrize("origin", [mcp.dual_era_gated], indirect=True)
def test_the_metadata_issuer_is_byte_for_byte_the_server_it_was_fetched_for(
    origin: Origin,
) -> None:
    named, _, document = _authorization_documents(origin)

    assert named == origin.url
    assert document["issuer"] == named
    assert document["code_challenge_methods_supported"] == ["S256"]


@pytest.mark.parametrize("origin", [mcp.issuer_differs], indirect=True)
def test_the_metadata_can_name_an_issuer_other_than_the_one_it_was_fetched_for(
    origin: Origin,
) -> None:
    named, _, document = _authorization_documents(origin)

    assert document["issuer"] == f"{named}/elsewhere"


@pytest.mark.parametrize("origin", [mcp.issuer_absent], indirect=True)
def test_the_metadata_can_name_no_issuer(origin: Origin) -> None:
    _, _, document = _authorization_documents(origin)

    assert "issuer" not in document
    assert document["token_endpoint"] == f"{origin.url}/token"


@pytest.mark.parametrize(
    ("origin", "version"),
    [(mcp.dual_era_gated, mcp.REPORTED_VERSION), (mcp.reporting_no_version, "")],
    indirect=["origin"],
)
def test_the_reported_version_is_the_same_in_both_revisions(origin: Origin, version: str) -> None:
    discovered = _modern(origin, "server/discover").result

    assert discovered["_meta"]["io.modelcontextprotocol/serverInfo"]["version"] == version
    assert _session(origin).opening["serverInfo"]["version"] == version


def test_a_server_that_stops_answering_refuses_every_connection_after_its_limit() -> None:
    with serving(mcp.stops_answering_after(2)) as served:
        assert _modern(served, "server/discover", credential=None).status == 200
        assert _modern(served, "tools/list", credential=None).status == 200
        with pytest.raises(urllib.error.URLError) as refused:
            _modern(served, "tools/list", credential=None)

    assert isinstance(refused.value.reason, ConnectionRefusedError)


@pytest.mark.parametrize("origin", [mcp.revisions_change_after_discovery], indirect=True)
def test_a_server_whose_revisions_change_refuses_the_modern_revision_after_discovery(
    origin: Origin,
) -> None:
    assert _modern(origin, "tools/list", credential=None).status == 200
    assert _modern(origin, "server/discover", credential=None).result["supportedVersions"] == [
        MODERN
    ]

    refused = _modern(origin, "tools/list", credential=None)
    assert refused.status == 400
    assert refused.headers["content-type"] == "application/json"
    assert refused.error["code"] == -32022
    assert refused.error["data"]["supported"] == list(mcp.NOW_SUPPORTED)


@pytest.mark.parametrize("origin", [mcp.legacy_answering_older_revision], indirect=True)
def test_a_legacy_server_can_answer_the_handshake_with_an_older_revision(origin: Origin) -> None:
    assert _initialize(origin).result["protocolVersion"] == mcp.OLDER_REVISION
    assert _modern(origin, "server/discover").error["code"] == -32601


# --- A2A ---------------------------------------------------------------------------------


def _rpc(origin: Origin, method: str, credential: str | None = None, **params: object) -> Reply:
    headers = {"A2A-Version": "1.0", **_bearer(credential)}
    return _post(f"{origin.url}{a2a.RPC_PATH}", method, params, headers)


def _card(origin: Origin) -> dict[str, Any]:
    return _get(f"{origin.url}{a2a.CARD_PATH}")


def _task_ids(reply: Reply) -> list[str]:
    return [task["id"] for task in reply.result.get("tasks", [])]


@pytest.mark.parametrize("origin", [a2a.owner_bound], indirect=True)
def test_an_owner_bound_agent_shows_each_caller_only_its_own_tasks(origin: Origin) -> None:
    card = _card(origin)
    assert card["supportedInterfaces"][0]["url"] == f"{origin.url}{a2a.RPC_PATH}"
    assert card["securityRequirements"] == [{"schemes": {a2a.SCHEME: {}}}]

    assert _task_ids(_rpc(origin, "ListTasks", a2a.CREDENTIAL_A, pageSize=5)) == [a2a.TASK_A]
    assert _task_ids(_rpc(origin, "ListTasks", a2a.CREDENTIAL_B, pageSize=5)) == []
    assert _rpc(origin, "GetTask", a2a.CREDENTIAL_B, id=a2a.TASK_A).error["code"] == -32001
    assert _rpc(origin, "GetTask", a2a.CREDENTIAL_A, id=a2a.TASK_A).result["id"] == a2a.TASK_A


@pytest.mark.parametrize("origin", [a2a.owner_bound], indirect=True)
@pytest.mark.parametrize("method", ["GetTask", "ListTasks", "GetExtendedAgentCard"])
def test_an_enforcing_agent_answers_a_caller_without_a_token_401(
    origin: Origin, method: str
) -> None:
    assert _rpc(origin, method, id=a2a.TASK_A).status == 401
    assert _rpc(origin, method, "a-token-nobody-issued", id=a2a.TASK_A).status == 401


@pytest.mark.parametrize("origin", [a2a.owner_bound], indirect=True)
def test_the_extended_card_is_served_to_a_caller_with_a_token(origin: Origin) -> None:
    assert _card(origin)["capabilities"]["extendedAgentCard"] is True
    skills = _rpc(origin, "GetExtendedAgentCard", a2a.CREDENTIAL_A).result["skills"]
    assert [skill["id"] for skill in skills] == ["lookup", "audit"]


@pytest.mark.parametrize("origin", [a2a.security_unenforced], indirect=True)
def test_an_agent_declaring_security_it_does_not_enforce_answers_anyone(origin: Origin) -> None:
    assert _card(origin)["securityRequirements"] == [{"schemes": {a2a.SCHEME: {}}}]
    assert _rpc(origin, "ListTasks", pageSize=1).status == 200
    assert _rpc(origin, "GetTask", id=a2a.TASK_A).error["code"] == -32001


@pytest.mark.parametrize("origin", [a2a.no_security], indirect=True)
def test_an_agent_declaring_no_security_answers_anyone(origin: Origin) -> None:
    card = _card(origin)

    assert "securitySchemes" not in card
    assert "securityRequirements" not in card
    assert _rpc(origin, "ListTasks", pageSize=1).result["totalSize"] == 0


@pytest.mark.parametrize("origin", [a2a.constant_owner], indirect=True)
def test_an_agent_with_a_constant_owner_shows_caller_a_task_to_caller_b(origin: Origin) -> None:
    assert _rpc(origin, "GetTask", a2a.CREDENTIAL_B, id=a2a.TASK_A).result["id"] == a2a.TASK_A
    assert _task_ids(_rpc(origin, "ListTasks", a2a.CREDENTIAL_B, pageSize=5)) == [a2a.TASK_A]
    assert _rpc(origin, "ListTasks", pageSize=1).status == 401


@pytest.mark.parametrize("origin", [a2a.extended_card_anonymous], indirect=True)
def test_an_agent_can_serve_its_extended_card_to_a_caller_without_a_token(origin: Origin) -> None:
    skills = _rpc(origin, "GetExtendedAgentCard").result["skills"]

    assert [skill["id"] for skill in skills] == ["lookup", "audit"]
    assert _rpc(origin, "ListTasks", pageSize=1).status == 401
    assert _rpc(origin, "GetTask", id=a2a.TASK_A).status == 401


@pytest.mark.parametrize("origin", [a2a.no_list_tasks], indirect=True)
def test_an_agent_without_task_listing_answers_list_tasks_unsupported(origin: Origin) -> None:
    assert _rpc(origin, "ListTasks", a2a.CREDENTIAL_A, pageSize=5).error["code"] == -32004
    assert _rpc(origin, "GetTask", a2a.CREDENTIAL_A, id=a2a.TASK_A).result["id"] == a2a.TASK_A


@pytest.mark.parametrize("origin", [a2a.card_defects], indirect=True)
def test_a_defective_card_lacks_a_description_and_requires_an_undeclared_scheme(
    origin: Origin,
) -> None:
    card = _card(origin)

    assert "description" not in card
    assert card["securityRequirements"] == [{"schemes": {a2a.UNDECLARED_SCHEME: {}}}]
    assert a2a.UNDECLARED_SCHEME not in card["securitySchemes"]


@pytest.mark.parametrize("origin", [a2a.interface_elsewhere], indirect=True)
def test_a_card_can_put_its_json_rpc_interface_on_another_origin(origin: Origin) -> None:
    interface = _card(origin)["supportedInterfaces"][0]

    assert interface["protocolBinding"] == "JSONRPC"
    assert interface["url"] == f"{a2a.other_origin(origin)}{a2a.RPC_PATH}"
    assert not interface["url"].startswith(origin.url)
    assert {seen.host for seen in origin.seen} == {urlsplit(origin.url).netloc}
