"""The audience probe, and the two ways it must refuse to reach a verdict."""

from base64 import urlsafe_b64decode as b64decode
from collections.abc import Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.report import Finding
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import McpServerTarget, forged_token
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.rules.mcp import McpTokenAudienceRule
from mcp_fixtures import CREDENTIAL, findings, guarded, outcomes, summaries, wide_open

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

RULE = McpTokenAudienceRule()


def test_a_server_that_answers_a_token_it_could_not_have_issued_is_critical() -> None:
    reported = findings(RULE, guarded(accepts_any_token=True), credential=CREDENTIAL)

    assert [f.severity for f in reported] == [Severity.CRITICAL]
    assert "was not validated" in reported[0].evidence.summary


def test_a_server_that_rejects_the_forged_token_reports_nothing() -> None:
    assert findings(RULE, guarded(), credential=CREDENTIAL) == []


def test_a_server_needing_no_credential_is_inconclusive_rather_than_critical() -> None:
    # The trap this rule exists around. An open server answers the forged token
    # because it answers everything, and reading that as a failure of audience
    # validation would put a CRITICAL on every development server there is.
    reported = findings(RULE, wide_open())

    assert outcomes(reported) == ["inconclusive"]
    assert "proves nothing" in summaries(reported)[0]


def test_the_token_presented_is_unmistakably_not_a_credential() -> None:
    # Quoted in the documentation, because an operator reading a critical finding is
    # entitled to see exactly what was sent to their server.
    header, payload, signature = forged_token().split(".")

    assert signature == "guardana-probe-not-a-valid-signature"
    assert "guardana.invalid" in b64decode(payload + "==").decode()
    assert '"alg":"none"' in b64decode(header + "==").decode()


class _AnsweringTheForgedToken:
    """A guarded server that answers every request bearing the forged token with one status."""

    def __init__(self, status: int) -> None:
        self.status = status
        self.inner = guarded()
        self.url = self.inner.url

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
        if (headers or {}).get("Authorization") == f"Bearer {forged_token()}":
            return RawReply(status=self.status, headers={}, body=b"")
        return self.inner(
            url,
            method=method,
            body=body,
            headers=headers,
            alongside=alongside,
            discovery=discovery,
        )


def _against(server: _AnsweringTheForgedToken) -> list[Finding]:
    target = McpServerTarget(
        server.url, credential=CREDENTIAL, sender=server, discovery_sender=server
    )
    return list(RULE.run(target, RuleContext()))


@pytest.mark.parametrize("status", [400, 404, 429, 500, 503])
def test_a_server_error_to_the_forged_token_is_inconclusive_not_a_pass(status: int) -> None:
    reported = _against(_AnsweringTheForgedToken(status))

    assert outcomes(reported) == ["inconclusive"]
    assert f"HTTP {status}" in summaries(reported)[0]


@pytest.mark.parametrize("status", [401, 403])
def test_an_authorization_refusal_of_the_forged_token_reports_nothing(status: int) -> None:
    assert _against(_AnsweringTheForgedToken(status)) == []
