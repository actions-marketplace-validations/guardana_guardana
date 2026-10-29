"""An address the server advertised reaches a finding without the query it carried.

Discovery documents and challenges are written by the server under test, and any
URL in them can carry a key in its query. Evidence travels to SARIF, the saved run
and the collector, and the evidence redactor does not recognise an arbitrary
`key=value`, so the rule has to show the address the way a target ref is shown.
"""

from collections.abc import Mapping
from types import SimpleNamespace
from typing import cast

import pytest
from _offline import refuse_name_lookups
from guardana.core.report import Finding
from guardana.core.rule import RuleContext
from guardana.core.target import Anonymous, Document, McpAuthorizationView, McpServerTarget
from guardana.core.target._mcp_http import DiscoveryScope, RawReply, RedirectRefusedError
from guardana.rules.mcp import (
    McpAuthorizationDiscoveryRule,
    McpDiscoveryTargetRule,
    McpIssuerIdentificationRule,
)
from mcp_fixtures import CONFORMING_RESOURCE, CREDENTIAL, ROUTABLE, findings, guarded, summaries

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_PLANTED = "planted-query-value"
_PLACEHOLDER = "[redacted:query:"


def _clean(reported: list[Finding]) -> None:
    assert reported, "the rule said nothing, so this test proves nothing"
    for finding in reported:
        assert _PLANTED not in finding.evidence.summary
        assert _PLANTED not in finding.evidence.detail


def test_a_refused_advertised_address_is_shown_without_its_query() -> None:
    server = guarded(challenge=f'Bearer resource_metadata="http://192.0.2.1/meta?key={_PLANTED}"')

    reported = findings(McpDiscoveryTargetRule(), server, credential=CREDENTIAL)

    _clean(reported)
    assert any(_PLACEHOLDER in line for line in summaries(reported))


def test_a_refused_redirect_is_shown_without_its_query() -> None:
    inner = guarded()

    def redirecting(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        if method == "GET":
            raise RedirectRefusedError(
                f"http://169.254.169.254/latest?key={_PLANTED}", "it is link-local"
            )
        return inner(
            url,
            method=method,
            body=body,
            headers=headers,
            alongside=alongside,
            discovery=discovery,
        )

    target = McpServerTarget(
        ROUTABLE, credential=CREDENTIAL, sender=redirecting, discovery_sender=redirecting
    )
    reported = list(McpDiscoveryTargetRule().run(target, RuleContext()))

    _clean(reported)
    assert any("169.254.169.254" in line for line in summaries(reported))


def test_the_metadata_address_named_in_a_finding_is_shown_without_its_query() -> None:
    advertised = f"https://93.184.215.14/.well-known/oauth-protected-resource?key={_PLANTED}"
    document = {k: v for k, v in CONFORMING_RESOURCE.items() if k != "resource"}
    server = guarded(
        challenge=f'Bearer resource_metadata="{advertised}"', resource_metadata=document
    )

    reported = findings(McpAuthorizationDiscoveryRule(), server, credential=CREDENTIAL)

    _clean(reported)
    assert any("declares no 'resource'" in line for line in summaries(reported))


def test_a_declared_resource_on_another_origin_is_shown_without_its_query() -> None:
    document = {**CONFORMING_RESOURCE, "resource": f"https://1.2.3.4/?key={_PLANTED}"}

    reported = findings(
        McpAuthorizationDiscoveryRule(), guarded(resource_metadata=document), credential=CREDENTIAL
    )

    _clean(reported)
    assert any("different origin" in line for line in summaries(reported))


def test_a_refused_issuer_is_shown_without_its_query() -> None:
    document = {
        **CONFORMING_RESOURCE,
        "authorization_servers": [f"https://10.0.0.5/?key={_PLANTED}"],
    }

    reported = findings(
        McpAuthorizationDiscoveryRule(), guarded(resource_metadata=document), credential=CREDENTIAL
    )

    _clean(reported)
    assert any("10.0.0.5" in line for line in summaries(reported))


def test_the_authorization_server_address_is_shown_without_its_query() -> None:
    view: McpAuthorizationView = cast(
        "McpAuthorizationView",
        SimpleNamespace(
            server=ROUTABLE,
            anonymous=Anonymous(status=401),
            protected_resource=None,
            authorization_server=Document(
                url=f"https://93.184.215.14/.well-known/oauth-authorization-server?key={_PLANTED}",
                status=200,
                content={"issuer": "https://93.184.215.14"},
            ),
        ),
    )
    rule = McpIssuerIdentificationRule()

    reported = list(rule.examine(view))

    _clean(reported)
    assert any(_PLACEHOLDER in line for line in summaries(reported))
