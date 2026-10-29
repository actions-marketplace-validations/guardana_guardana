"""Scopes that cannot express least privilege, and a challenge that names none."""

import pytest
from _offline import refuse_name_lookups
from guardana.core.severity import Severity
from guardana.rules.mcp import McpScopeBreadthRule
from mcp_fixtures import (
    CONFORMING_RESOURCE,
    CREDENTIAL,
    ServingAt,
    findings,
    findings_through,
    guarded,
    outcomes,
    summaries,
    wide_open,
)

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpScopeBreadthRule()


def test_narrow_scopes_and_a_scoped_challenge_report_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_wildcard_scope_is_a_finding() -> None:
    document = {**CONFORMING_RESOURCE, "scopes_supported": ["tools:read", "*"]}

    reported = findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.MEDIUM]
    assert "cannot be revoked without revoking every workflow" in reported[0].evidence.summary


def test_an_omnibus_scope_on_the_authorization_server_is_a_finding() -> None:
    document = {"issuer": "https://93.184.215.14", "scopes_supported": ["full-access"]}

    reported = findings(RULE, guarded(authorization_metadata=document), credential=CREDENTIAL)

    assert any("authorization server metadata" in line for line in summaries(reported))


def test_a_scope_that_merely_reads_broadly_is_not_a_wildcard() -> None:
    # `files:read-all` is an ordinary scope name. Matching on substrings would make
    # this rule fire on half the deployments in existence and get it excluded.
    document = {**CONFORMING_RESOURCE, "scopes_supported": ["files:read-all", "mcp:tools-basic"]}

    assert findings(RULE, guarded(resource_metadata=document), credential=CREDENTIAL) == []


def test_a_challenge_naming_no_scope_is_reported_low() -> None:
    # A SHOULD rather than a MUST, and graded accordingly: without it a general
    # purpose client has nothing to ask for but everything.
    reported = findings(RULE, guarded(challenge="Bearer"), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.LOW]
    assert "will ask for all of them" in reported[0].evidence.summary


def test_a_server_publishing_no_metadata_at_all_is_declined_rather_than_passed() -> None:
    # Silence from a rule here means "the invariant holds". This server published
    # nothing to read scopes from, so a silent rule would be reporting that its
    # scopes are narrow enough on evidence nobody ever saw — and the reader cannot
    # tell that apart from the conforming server two tests up.
    reported = findings(
        RULE,
        guarded(resource_metadata=None, authorization_metadata=None),
        credential=CREDENTIAL,
    )

    assert outcomes(reported) == ["inconclusive"]
    assert "no metadata document" in reported[0].evidence.summary


_AUTHORIZATION_DOCUMENT = "https://93.184.215.14/.well-known/oauth-authorization-server"


def _unreadable_authorization_server(**overrides: object) -> ServingAt:
    # The second well-known path answers 404, which must not hide the page at the first.
    server = guarded(authorization_metadata=None, **overrides)
    return ServingAt(server, _AUTHORIZATION_DOCUMENT, b"<html>sign in</html>")


def test_narrow_resource_scopes_beside_an_unread_authorization_server_are_not_clean() -> None:
    reported = findings_through(RULE, _unreadable_authorization_server(), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "oauth-authorization-server could not be read" in summaries(reported)[0]
    assert "only the protected resource metadata" in summaries(reported)[0]


def test_a_wildcard_in_the_half_that_was_read_is_still_a_finding() -> None:
    wildcard = {**CONFORMING_RESOURCE, "scopes_supported": ["*"]}

    reported = findings_through(
        RULE, _unreadable_authorization_server(resource_metadata=wildcard), credential=CREDENTIAL
    )

    assert outcomes(reported)[0] is None
    assert "['*']" in summaries(reported)[0]


def test_an_authorization_server_every_address_of_which_was_refused_is_unseen() -> None:
    resource = {**CONFORMING_RESOURCE, "authorization_servers": ["https://169.254.169.254"]}

    reported = findings(RULE, guarded(resource_metadata=resource), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert "169.254.169.254" in summaries(reported)[0]


def test_an_authorization_server_publishing_no_metadata_advertises_no_scopes() -> None:
    assert findings(RULE, guarded(authorization_metadata=None), credential=CREDENTIAL) == []


@pytest.mark.parametrize("status", [429, 500, 503])
def test_an_authorization_server_failing_at_its_metadata_addresses_is_unseen(status: int) -> None:
    reported = findings(RULE, guarded(authorization_metadata_status=status), credential=CREDENTIAL)

    assert outcomes(reported) == ["inconclusive"]
    assert f"HTTP {status}" in summaries(reported)[0]


def test_an_authorization_server_answering_410_advertises_no_scopes() -> None:
    assert findings(RULE, guarded(authorization_metadata_status=410), credential=CREDENTIAL) == []


def test_a_server_open_to_anyone_is_inconclusive_rather_than_silent() -> None:
    # A wildcard an open server publishes is never fetched; silence would read as
    # "this server's scopes are narrow".
    server = wide_open(resource_metadata={**CONFORMING_RESOURCE, "scopes_supported": ["*"]})

    reported = findings(RULE, server)

    assert outcomes(reported) == ["inconclusive"]
    assert "answers an anonymous caller" in summaries(reported)[0]
    assert "never fetched" in summaries(reported)[0]
    assert "scopes" in summaries(reported)[0]
