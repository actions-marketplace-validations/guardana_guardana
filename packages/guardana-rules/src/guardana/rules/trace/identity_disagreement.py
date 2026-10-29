from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP01_2025
from guardana.core.trace import CredentialKind, CredentialRef, Identity, Span, SpanKind, Trace
from guardana.rules.trace import _samples
from guardana.rules.trace._base import TraceRule

_NEVER_AUDIENCE_BOUND = frozenset(
    {CredentialKind.API_KEY, CredentialKind.BASIC, CredentialKind.MTLS}
)


class IdentityDisagreementRule(TraceRule):
    """A token's audience is not the resource it was presented to.

    Identity in a trace is three claims that can disagree: the credential the caller
    presented, the audience its token names, and the resource the callee says it is.
    Audience binding is the control that stops a token minted for one service being
    replayed against another, and it only works when those three agree.

    This is the distinction the MCP work established, written as a check. A schema with
    one `credential` field could not express it, which is why the model has three.
    """

    meta = RuleMeta(
        id="guardana.trace.identity_disagreement",
        title="A token was presented to a resource outside its audience",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP01_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_IDENTITY}),
        detection=Detection.INVARIANT,
    )

    claim = "whether a token was presented outside its audience is not established"

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a mismatched audience, a matching one, and a matching one beside a lost record."""
        return materialise(
            (
                _samples.sample(
                    "a token minted for billing presented to the reports service",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(_presented("https://billing.invalid/")),
                ),
                _samples.sample(
                    "a token presented to the resource its audience names",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(_presented(_RESOURCE)),
                ),
                _samples.sample(
                    "a matching presentation beside a record the reader could not interpret",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_presented(_RESOURCE), unreadable=1),
                    "the unread record may be a presentation outside its audience",
                ),
            )
        )

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare audience against claimed resource, and decline where either is absent.

        Two thirds of a disagreement is not a disagreement, so a presented token whose
        audience or callee nobody recorded is never reported as a mismatch — and never
        passed either: those presentations are declined in one aggregated line. An empty
        audience means nobody wrote one down, which is the same fact as an absent claim.
        A credential stated to be a kind that is never audience-bound — an API key, basic
        credentials, a client certificate — and naming no audience is not part of the
        question. One of kind `other` is undecided, because a trace that omits the kind
        reads as `other` and may be carrying a bearer token.
        """
        undecided: list[str] = []
        for span in trace.spans:
            identity = span.identity
            credential = identity.credential if identity is not None else None
            if credential is None:
                continue
            if not credential.audience and credential.kind in _NEVER_AUDIENCE_BOUND:
                continue
            resource = identity.claimed_resource if identity is not None else None
            if resource is None or not credential.audience:
                undecided.append(span.span_id)
                continue
            if any(self._covers(audience, resource) for audience in credential.audience):
                continue
            yield self.finding(
                trace,
                f"the credential presented in span {span.span_id} names audience "
                f"{', '.join(credential.audience)} while the callee claims to be {resource} — "
                f"a token accepted outside its audience is a token that can be replayed from "
                f"one service against another",
                span=span,
            )
        if undecided:
            yield self.unverified(
                trace,
                f"{len(undecided)} presented token(s) (span {', '.join(undecided)}) record no "
                f"audience or no callee, so {self.claim} for them",
            )

    def _covers(self, audience: str, resource: str) -> bool:
        """Whether an audience value names this resource.

        Compared after trimming a trailing slash, because `https://a/` and `https://a`
        are the same resource and an operator writing one of each is not a finding.
        Nothing looser than that: a prefix match would read `https://a.evil.test` as
        covered by `https://a`.
        """
        return audience.rstrip("/") == resource.rstrip("/")


_RESOURCE = "https://reports.invalid"


def _presented(audience: str) -> Span:
    """Build a call to the reports service carrying a token minted for `audience`."""
    return Span(
        span_id="s1",
        kind=SpanKind.TOOL_EXECUTION,
        name="fetch_report",
        identity=Identity(
            credential=CredentialRef(
                kind=CredentialKind.BEARER, digest="sha256:token", audience=(audience,)
            ),
            claimed_resource=_RESOURCE,
        ),
    )
