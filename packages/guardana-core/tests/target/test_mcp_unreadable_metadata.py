"""A metadata document that came back but could not be read is a gap, not a refusal or a 404."""

from collections.abc import Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

ROUTABLE = "https://93.184.215.14/mcp"
CREDENTIAL = "operator"


@pytest.mark.parametrize("body", [b"<html>sign in</html>", b"[]"], ids=["not-json", "not-object"])
def test_an_unreadable_resource_document_is_recorded_as_an_error(body: bytes) -> None:
    server = ScriptedMcpServer(ROUTABLE, credential=CREDENTIAL, resource_metadata_body=body)
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )

    document = target.authorization().protected_resource

    assert document is not None
    assert not document.readable
    assert document.refused is None
    assert document.error is not None
    assert target.authorization().authorization_server is None


def test_the_raw_body_is_served_in_place_of_the_document() -> None:
    server = ScriptedMcpServer(
        ROUTABLE,
        resource_metadata={"resource": ROUTABLE},
        resource_metadata_body=b"not json",
    )

    reply = server("https://93.184.215.14/.well-known/oauth-protected-resource", method="GET")

    assert reply.status == 200
    assert reply.body == b"not json"


_ADVERTISED = "https://93.184.215.14/metadata/resource"


class _AdvertisedPageUnreadable:
    """A gated server whose advertised resource document is a page; the well-known paths 404."""

    def __init__(self) -> None:
        self.server = ScriptedMcpServer(
            ROUTABLE,
            credential=CREDENTIAL,
            challenge=f'Bearer resource_metadata="{_ADVERTISED}"',
        )

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
        if method == "GET" and url == _ADVERTISED:
            return RawReply(status=200, headers={}, body=b"<html>sign in</html>")
        return self.server(url, method=method, body=body, headers=headers)


def test_an_unreadable_document_is_not_hidden_by_a_later_404() -> None:
    sender = _AdvertisedPageUnreadable()
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=sender, discovery_sender=sender
    )

    document = target.authorization().protected_resource

    assert document is not None
    assert document.url == _ADVERTISED
    assert document.error is not None
    assert document.status == 200


def test_404s_everywhere_are_still_not_published() -> None:
    server = ScriptedMcpServer(ROUTABLE, credential=CREDENTIAL)
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server
    )

    document = target.authorization().protected_resource

    assert document is not None
    assert document.error is None
    assert document.status == 404


def _gated(**behaviour: object) -> McpServerTarget:
    server = ScriptedMcpServer(ROUTABLE, credential=CREDENTIAL, **behaviour)  # type: ignore[arg-type]
    return McpServerTarget(ROUTABLE, credential=CREDENTIAL, sender=server, discovery_sender=server)


@pytest.mark.parametrize("status", [404, 410])
def test_only_404_and_410_say_a_document_is_not_published(status: int) -> None:
    document = _gated(resource_metadata_status=status).authorization().protected_resource

    assert document is not None
    assert document.error is None
    assert document.status == status


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_any_other_error_status_leaves_the_document_unread(status: int) -> None:
    document = _gated(resource_metadata_status=status).authorization().protected_resource

    assert document is not None
    assert not document.readable
    assert document.status == status
    assert document.error is not None
    assert f"HTTP {status}" in document.error


def test_an_unavailable_authorization_server_document_is_unread() -> None:
    target = _gated(
        resource_metadata={
            "resource": "https://93.184.215.14",
            "authorization_servers": ["https://93.184.215.14"],
        },
        authorization_metadata={"issuer": "https://93.184.215.14"},
        authorization_metadata_status=503,
    )

    document = target.authorization().authorization_server

    assert document is not None
    assert document.status == 503
    assert document.error is not None


class _AdvertisedUnavailable:
    """A gated server whose advertised resource document answers 503; the well-known paths 404."""

    def __init__(self) -> None:
        self.server = ScriptedMcpServer(
            ROUTABLE,
            credential=CREDENTIAL,
            challenge=f'Bearer resource_metadata="{_ADVERTISED}"',
        )

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
        if method == "GET" and url == _ADVERTISED:
            return RawReply(status=503, headers={}, body=b"")
        return self.server(url, method=method, body=body, headers=headers)


def test_a_503_is_not_turned_into_not_published_by_a_later_404() -> None:
    sender = _AdvertisedUnavailable()
    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=sender, discovery_sender=sender
    )

    document = target.authorization().protected_resource

    assert document is not None
    assert document.url == _ADVERTISED
    assert document.status == 503
    assert document.error is not None


def test_a_status_set_for_a_document_is_served_in_its_place() -> None:
    server = ScriptedMcpServer(
        ROUTABLE,
        resource_metadata={"resource": ROUTABLE},
        authorization_metadata={"issuer": ROUTABLE},
        resource_metadata_status=503,
        authorization_metadata_status=429,
    )

    resource = server("https://93.184.215.14/.well-known/oauth-protected-resource", method="GET")
    authorization = server(
        "https://93.184.215.14/.well-known/oauth-authorization-server", method="GET"
    )

    assert (resource.status, resource.body) == (503, b"")
    assert (authorization.status, authorization.body) == (429, b"")
