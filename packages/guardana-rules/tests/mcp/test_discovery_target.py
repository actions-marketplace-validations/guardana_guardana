"""Addresses a server hands its client, and the ones this client will not follow."""

import pytest
from _offline import refuse_name_lookups
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpDiscoveryTargetRule
from mcp_fixtures import (
    CONFORMING_RESOURCE,
    CREDENTIAL,
    LOOPBACK,
    ServingAt,
    findings,
    findings_through,
    guarded,
    outcomes,
    summaries,
    wide_open,
)

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpDiscoveryTargetRule()
_METADATA_ENDPOINT = "169.254.169.254/.well-known/oauth-protected-resource"


def test_a_conforming_server_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_challenge_pointing_at_the_cloud_metadata_endpoint_is_a_finding() -> None:
    server = guarded(challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"')

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert len(reported) == 1
    assert "169.254.169.254" in reported[0].evidence.summary
    assert "must not be sent to" in reported[0].evidence.summary


def test_the_dangerous_address_is_never_fetched() -> None:
    # The refusal *is* the finding. A scanner that followed the URL to prove it was
    # dangerous would have performed the attack in order to report it.
    server = guarded(challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"')

    findings(RULE, server, credential=CREDENTIAL)

    assert not [url for _, url, _ in server.requests if "169.254.169.254" in url]


def test_a_good_document_elsewhere_does_not_bury_the_bad_pointer() -> None:
    # The case that made refusals a list of their own: a server can advertise the
    # metadata endpoint *and* serve a perfectly valid document at the well-known
    # path, and following the good one would lose the pointer entirely.
    server = guarded(challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"')

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert reported, "the advertised address was lost behind the document that worked"


def test_an_authorization_server_on_a_private_address_is_a_finding() -> None:
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["https://10.0.0.5"]}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert any("10.0.0.5" in line for line in summaries(reported))
    assert any("inside the network running this scan" in line for line in summaries(reported))


def test_a_refused_address_named_after_the_first_authorization_server_is_a_finding() -> None:
    issuers = ["https://93.184.215.14", "https://169.254.169.254"]
    server = guarded(resource_metadata={**CONFORMING_RESOURCE, "authorization_servers": issuers})

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == [None, None]
    assert "169.254.169.254" in reported[0].evidence.summary
    assert not [url for _, url, _ in server.requests if "169.254.169.254" in url]


def test_a_further_authorization_server_left_unread_is_inconclusive() -> None:
    issuers = ["https://93.184.215.14", "https://93.184.215.15"]
    server = guarded(resource_metadata={**CONFORMING_RESOURCE, "authorization_servers": issuers})

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "93.184.215.15" in reported[0].evidence.summary
    assert not [url for _, url, _ in server.requests if "93.184.215.15" in url]


def test_a_local_server_may_point_at_a_local_authorization_server() -> None:
    # Otherwise this rule is noise on the first machine anybody tries it on.
    document = {
        "resource": "http://127.0.0.1:3000",
        "authorization_servers": ["http://127.0.0.1:9000"],
    }
    server = ScriptedMcpServer(
        LOOPBACK,
        tools=[],
        credential=CREDENTIAL,
        resource_metadata=document,
        authorization_metadata={
            "issuer": "http://127.0.0.1:9000",
            "code_challenge_methods_supported": ["S256"],
        },
    )

    assert findings(RULE, server, credential=CREDENTIAL) == []


@pytest.mark.parametrize("body", [b"<html>sign in</html>", b"[]"], ids=["not-json", "not-object"])
def test_a_resource_document_that_cannot_be_read_is_inconclusive_rather_than_clean(
    body: bytes,
) -> None:
    # The document names the authorization server, so an unread one hides an address.
    reported = findings(RULE, guarded(resource_metadata_body=body), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be read" in summaries(reported)[0]


def test_an_unreadable_document_does_not_bury_a_refused_pointer() -> None:
    server = guarded(
        challenge=f'Bearer resource_metadata="http://{_METADATA_ENDPOINT}"',
        resource_metadata_body=b"<html>sign in</html>",
    )

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == [None, "inconclusive"]
    assert _METADATA_ENDPOINT in summaries(reported)[0]


def test_a_server_publishing_no_resource_document_directs_a_client_nowhere() -> None:
    assert findings(RULE, guarded(resource_metadata=None), credential=CREDENTIAL) == []


def test_an_unreadable_advertised_document_is_not_buried_by_404s_at_the_well_known_paths() -> None:
    advertised = "https://93.184.215.14/metadata/resource"
    server = guarded(challenge=f'Bearer resource_metadata="{advertised}"', resource_metadata=None)

    reported = findings_through(
        RULE, ServingAt(server, advertised, b"<html>sign in</html>"), credential=CREDENTIAL
    )

    assert outcomes(reported) == ["inconclusive"]
    assert "metadata/resource could not be read" in summaries(reported)[0]


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_resource_document_answering_an_error_hides_the_next_address(status: int) -> None:
    reported = findings(RULE, guarded(resource_metadata_status=status), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert f"HTTP {status}" in summaries(reported)[0]


def test_a_resource_document_that_is_gone_directs_a_client_nowhere() -> None:
    assert findings(RULE, guarded(resource_metadata_status=410), credential=CREDENTIAL) == []


def test_a_server_open_to_anyone_is_inconclusive_rather_than_silent() -> None:
    # The addresses an open server names are never followed, so "it directs a client
    # nowhere it must not go" would be a claim nobody checked.
    server = wide_open(
        resource_metadata={**CONFORMING_RESOURCE, "authorization_servers": ["https://10.0.0.5"]}
    )

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "answers an anonymous caller" in summaries(reported)[0]
    assert "never fetched" in summaries(reported)[0]
