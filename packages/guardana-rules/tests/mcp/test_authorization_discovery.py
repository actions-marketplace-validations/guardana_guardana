"""Whether a protected server publishes an authorization surface a client can use."""

import pytest
from _offline import refuse_name_lookups
from guardana.rules.mcp import McpAuthorizationDiscoveryRule
from mcp_fixtures import (
    CONFORMING_AUTHORIZATION,
    CONFORMING_RESOURCE,
    CREDENTIAL,
    ELSEWHERE,
    findings,
    guarded,
    outcomes,
    summaries,
    wide_open,
)

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpAuthorizationDiscoveryRule()


def test_a_conforming_server_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_protected_server_publishing_no_metadata_is_a_finding() -> None:
    reported = findings(RULE, guarded(resource_metadata=None), credential=CREDENTIAL)

    assert len(reported) == 1
    assert "is not published" in reported[0].evidence.summary
    assert outcomes(reported) == [None], "a missing MUST is a finding, not an unanswered question"


def test_metadata_naming_no_authorization_server_is_a_finding() -> None:
    document = {key: value for key, value in CONFORMING_RESOURCE.items() if key != "resource"}
    document["authorization_servers"] = []

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert any("names no authorization server" in line for line in summaries(reported))
    assert any("declares no 'resource'" in line for line in summaries(reported))


def test_a_resource_naming_another_origin_is_a_finding() -> None:
    # Audience binding is only worth anything if the audience is this server. A
    # document pointing somewhere else makes every conforming client request a
    # token for the wrong resource — correctly, and uselessly.
    document = {**CONFORMING_RESOURCE, "resource": ELSEWHERE}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert [f"{ELSEWHERE!r}" in line for line in summaries(reported)] == [True]
    assert "different origin" in summaries(reported)[0]


def test_an_authorization_server_without_pkce_discovery_is_a_finding() -> None:
    # The specification says a client that cannot find this field MUST refuse to
    # proceed, so a deployment without it is one no conforming client can use.
    document = {
        key: value
        for key, value in CONFORMING_AUTHORIZATION.items()
        if key != "code_challenge_methods_supported"
    }

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert any("code_challenge_methods_supported" in line for line in summaries(reported))


def test_an_authorization_server_offering_only_plain_pkce_is_a_finding() -> None:
    document = {**CONFORMING_AUTHORIZATION, "code_challenge_methods_supported": ["plain"]}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert any("'S256'" in line for line in summaries(reported))


def test_a_server_that_needs_no_credential_is_inconclusive_rather_than_silent() -> None:
    # Discovery is never attempted on an open server, so a broken surface it publishes
    # goes unread, and the rule that reports the open server may be excluded.
    server = wide_open(resource_metadata={**CONFORMING_RESOURCE, "resource": ELSEWHERE})

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "answers an anonymous caller" in summaries(reported)[0]
    assert "never fetched" in summaries(reported)[0]
    assert "guardana.mcp.unauthenticated_access" in summaries(reported)[0]


def test_an_authorization_server_nobody_could_reach_leaves_pkce_unsettled() -> None:
    # The resource document is perfect and names an issuer a client must not follow,
    # so every discovery address for it is refused. PKCE is then a question this run
    # never asked — and staying silent about it reads exactly like the conforming
    # server in the first test.
    document = {**CONFORMING_RESOURCE, "authorization_servers": ["http://169.254.169.254/"]}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "PKCE" in reported[0].evidence.summary
    assert "169.254.169.254" in reported[0].evidence.summary


def test_authorization_server_metadata_naming_no_issuer_is_a_finding() -> None:
    document = {key: value for key, value in CONFORMING_AUTHORIZATION.items() if key != "issuer"}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [RULE.meta.severity]
    assert "names no issuer" in summaries(reported)[0]
    assert outcomes(reported) == [None]


def test_an_issuer_that_is_not_a_string_names_no_issuer() -> None:
    document = {**CONFORMING_AUTHORIZATION, "issuer": 42}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert ["names no issuer" in line for line in summaries(reported)] == [True]


def test_an_issuer_other_than_the_one_the_document_was_fetched_for_is_a_finding() -> None:
    document = {**CONFORMING_AUTHORIZATION, "issuer": ELSEWHERE}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert len(reported) == 1
    assert f"{ELSEWHERE!r}" in summaries(reported)[0]
    assert "'https://93.184.215.14'" in summaries(reported)[0]


def test_issuers_are_compared_as_strings_so_a_trailing_slash_is_a_mismatch() -> None:
    document = {**CONFORMING_AUTHORIZATION, "issuer": "https://93.184.215.14/"}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert ["must not use" in line for line in summaries(reported)] == [True]


def test_a_document_served_but_unreadable_is_reported_as_what_came_back() -> None:
    # A client cannot use it either way, but "not published" would be false.
    server = guarded(resource_metadata_body=b"<html>sign in</html>")

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == [None]
    assert "not published" not in summaries(reported)[0]
    assert "answered HTTP 200 but the reply is not a JSON object" in summaries(reported)[0]


@pytest.mark.parametrize(
    "unavailable", ["resource_metadata_status", "authorization_metadata_status"]
)
def test_a_metadata_document_answering_503_is_unread_rather_than_unpublished(
    unavailable: str,
) -> None:
    server = guarded(**{unavailable: 503})

    reported = findings(RULE, server, credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "not published" not in summaries(reported)[0]
    assert "HTTP 503" in summaries(reported)[0]


def test_a_metadata_document_answering_410_is_not_published() -> None:
    reported = findings(RULE, guarded(resource_metadata_status=410), credential=CREDENTIAL)

    assert outcomes(reported) == [None]
    assert "is not published" in summaries(reported)[0]
