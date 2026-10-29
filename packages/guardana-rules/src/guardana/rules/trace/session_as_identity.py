from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025
from guardana.core.trace import (
    CredentialKind,
    CredentialRef,
    Identity,
    SessionRef,
    Span,
    SpanKind,
    ToolExecution,
    Trace,
    TraceTruncation,
)
from guardana.rules.trace import _samples
from guardana.rules.trace._base import TraceRule, records_actions


class SessionAsIdentityRule(TraceRule):
    """A step that changed something identified itself with a session and nothing else.

    > MCP Servers **MUST NOT** use sessions for authentication.

    It is not an MCP-only mistake, and a trace is where it becomes visible on any
    protocol: a session id says which connection this is, never who it belongs to.
    Anything that guesses or steals the id inherits whatever the session could do.

    Deliberately silent on a read-only step. An unauthenticated read is a different
    question with its own answer, and firing on every recorded read would bury the case
    where an unidentified caller *changed* something.
    """

    meta = RuleMeta(
        id="guardana.trace.session_as_identity",
        title="A state-changing step was identified by a session rather than a credential",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_IDENTITY}),
        detection=Detection.INVARIANT,
    )

    claim = "whether a state-changing step was authenticated is not established"

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a write on a bare session, one with a credential, and one cut by the reader."""
        return materialise(
            (
                _samples.sample(
                    "a record update identified by its session id alone",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(_update(credential=None)),
                ),
                _samples.sample(
                    "a record update presenting a credential beside its session",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(_update(credential=_CREDENTIAL)),
                ),
                _samples.sample(
                    "an authenticated update in a trace the reader stopped at its ceiling",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _update(credential=_CREDENTIAL), truncated=TraceTruncation.READ_LIMIT
                    ),
                    "a later write on a bare session may be in the part that was not read",
                ),
            )
        )

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Find spans that changed something while carrying only a session reference.

        `changes_something` is conservative on purpose: an executed side effect, or a
        tool the producer stated mutates. A tool whose mutation is unknown does not
        count, because guessing from its name would put this verdict on a heuristic
        nobody measured. A trace recording neither tool calls nor effects cannot show a
        change at all, so a session-only step there is declined rather than passed; so is
        one in a trace where no span records an executed effect or a tool whose mutation
        the producer stated, because a requested tool call shows no change either way.
        Otherwise each session-only step is decided on its own: one that ran a tool whose
        mutation is unknown and shows no executed effect is declined, in one aggregated
        line, whatever other spans state about their own tools.
        """
        bare = [
            span
            for span in trace.spans
            if span.identity is not None and span.identity.is_session_only
        ]
        if bare and not records_actions(trace):
            yield self.unverified(
                trace,
                f"{len(bare)} step(s) identified only by a session, and this trace records "
                f"neither tool calls nor effects, so {self.claim}",
            )
            return
        if bare and not any(_shows_whether_it_changed(span) for span in trace.spans):
            yield self.unverified(
                trace,
                f"{len(bare)} step(s) identified only by a session, and no span in this trace "
                f"records an executed effect or whether a tool it ran mutates, so {self.claim}",
            )
            return
        undecided: list[str] = []
        for span in bare:
            identity = span.identity
            if identity is None:
                continue
            if not span.changes_something():
                if _mutation_unknown(span):
                    undecided.append(span.span_id)
                continue
            session = identity.session
            protocol = f" ({session.protocol})" if session is not None and session.protocol else ""
            yield self.finding(
                trace,
                f"span {span.span_id} changed something while presenting only a session id"
                f"{protocol} — a session says which connection this is, never who it belongs "
                f"to, so anything holding the id inherits what the session could do",
                span=span,
            )
        if undecided:
            yield self.unverified(
                trace,
                f"{len(undecided)} step(s) identified only by a session (span "
                f"{', '.join(undecided)}) ran a tool whose mutation is not recorded and show no "
                f"executed effect, so {self.claim} for them",
            )


def _mutation_unknown(span: Span) -> bool:
    """Whether this span ran a tool without saying whether it mutates, and shows no effect."""
    return span.tool is not None and span.tool.mutates is None and not span.executed_effects()


def _shows_whether_it_changed(span: Span) -> bool:
    """Whether this span records an executed effect or a tool whose mutation is stated."""
    return bool(span.executed_effects()) or (
        span.tool is not None and span.tool.mutates is not None
    )


_CREDENTIAL = CredentialRef(kind=CredentialKind.BEARER, digest="sha256:token")


def _update(*, credential: CredentialRef | None) -> Span:
    """Build a tool call the producer recorded as mutating, on an MCP session."""
    return Span(
        span_id="s1",
        kind=SpanKind.TOOL_EXECUTION,
        name="update_record",
        tool=ToolExecution(name="update_record", mutates=True),
        identity=Identity(
            credential=credential, session=SessionRef(id="session-1", protocol="mcp")
        ),
    )
