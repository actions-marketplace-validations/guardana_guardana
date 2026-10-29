from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM03_2026, OWASP_MCP02_2025
from guardana.core.trace import Consent, Delegation, Span, SpanKind, Trace
from guardana.rules.trace import _samples
from guardana.rules.trace._base import TraceRule
from guardana.rules.trace._order import Placement, placed


class ConsentScopeExceededRule(TraceRule):
    """A hop exercised a scope the client was never granted.

    Consent is recorded **per client**, not per user, and that is the distinction the
    MCP work paid for: the confused deputy works because a decision recorded against a
    user gets read as a decision about a client. A model keyed on the subject cannot
    express the bug, so this reads the grant by client and the exercise by hop.

    A scope in use with no matching grant is privilege nobody agreed to — the escalation
    OWASP calls scope creep, seen from the inside rather than inferred from what a
    server advertises.
    """

    meta = RuleMeta(
        id="guardana.trace.consent_scope_exceeded",
        title="A scope was exercised that no consent record granted",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP02_2025, OWASP_ASI03_2026, OWASP_LLM03_2026),
        required_capabilities=frozenset(
            {Capability.READ_TRACE, Capability.READ_CONSENT, Capability.READ_DELEGATION}
        ),
        detection=Detection.INVARIANT,
    )

    claim = "whether an ungranted scope was exercised is not established"

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a scope beyond the grant, one within it, and a hop that kept its scopes quiet."""
        return materialise(
            (
                _samples.sample(
                    "a client granted read access calling with read and write",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(_granted(), _used(("docs:read", "docs:write"))),
                ),
                _samples.sample(
                    "a client calling with the one scope it was granted",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(_granted(), _used(("docs:read",))),
                ),
                _samples.sample(
                    "a client whose call does not record which scopes it used",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_granted(), _used(None)),
                ),
            )
        )

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare each hop's scopes against what its client was granted by then.

        A grant counts for a hop when it is recorded in the hop's span or an earlier one,
        unless its own time is after the hop's step ended, or in a later span whose own
        time is no later than the start of the step. A scope granted only by a consent
        shown, by a time after the step ended, to come later is a finding wherever the
        consent is written; one granted only by a later consent nothing places — no time
        recorded, or one inside the step's window — is declined by name. A consent that says
        nothing about its scopes makes "this scope was never granted" unprovable for that
        client, and a hop that says nothing about the scopes it used makes "nothing
        ungranted was used" unprovable for that hop; the rule declines by name for both. A
        grant of `()` is different and is believed, and so is the absence of any consent
        for a client in a trace that records consent: either way the client was granted
        nothing, and a hop exercising a scope is a finding.
        """
        silent = self._silent(trace)
        if silent:
            yield self.unverified(
                trace,
                f"the consent record(s) for {', '.join(sorted(silent))} do not say which "
                f"scopes were granted, so {self.claim} for them",
            )
        consents = self._by_client(trace, silent)
        unrecorded: list[str] = []
        unordered: list[str] = []
        for index, span in enumerate(trace.spans):
            for hop in span.delegations:
                if hop.actor in silent:
                    continue
                if hop.scopes is None:
                    unrecorded.append(f"{hop.actor} across {hop.boundary!r} in span {span.span_id}")
                    continue
                known, allowed, late, unplaced = self._granted_for(
                    consents.get(hop.actor, []), index, span
                )
                exceeded = sorted(set(hop.scopes) - allowed)
                waiting = [scope for scope in exceeded if scope in unplaced]
                if waiting:
                    unordered.append(f"{', '.join(waiting)} by {hop.actor} in span {span.span_id}")
                exceeded = [scope for scope in exceeded if scope not in unplaced]
                if exceeded:
                    yield self.finding(
                        trace,
                        f"{hop.actor} exercised scope(s) {', '.join(exceeded)} across "
                        f"{hop.boundary!r} in span {span.span_id}, and "
                        f"{self._grant(known, allowed, late, exceeded)}",
                        span=span,
                    )
        if unrecorded:
            yield self.unverified(
                trace,
                f"the delegation(s) by {'; '.join(unrecorded)} do not say which scopes were "
                f"used, so {self.claim} for them",
            )
        if unordered:
            yield self.unverified(
                trace,
                f"the scope(s) {'; '.join(unordered)} are granted only by a consent recorded "
                f"in a later span, with no time that orders the two, so {self.claim} for them",
            )

    def _silent(self, trace: Trace) -> set[str]:
        """Return the clients with a granting consent that does not say which scopes it grants.

        One silent record poisons that client for the whole trace, because it is enough to
        make the absence unprovable wherever it sits.
        """
        return {
            consent.client
            for span in trace.spans
            for consent in span.consents
            if consent.granted and consent.scopes is None
        }

    def _by_client(self, trace: Trace, silent: set[str]) -> dict[str, list[tuple[int, Consent]]]:
        """Index the consents of every client not poisoned by a silent one, with their span."""
        consents: dict[str, list[tuple[int, Consent]]] = {}
        for index, span in enumerate(trace.spans):
            for consent in span.consents:
                if consent.client not in silent:
                    consents.setdefault(consent.client, []).append((index, consent))
        return consents

    def _granted_for(
        self, consents: list[tuple[int, Consent]], index: int, hop_span: Span
    ) -> tuple[bool, set[str], set[str], set[str]]:
        """Return what the hop's client was granted by `hop_span`, and what later consents add.

        `consents` holds only the records for the hop's client. The first value says
        whether any consent for the client counts by then; a refusal registers the client
        and grants nothing, which is what makes the refusal mean something. The last two
        are the scopes granted by a consent shown to come after the hop, wherever it is
        written, and those granted by a later consent nothing places.
        """
        known = False
        allowed: set[str] = set()
        late: set[str] = set()
        unplaced: set[str] = set()
        for at, consent in consents:
            placement = placed(consent.recorded_at, hop_span)
            if at <= index and placement is not Placement.AFTER:
                placement = Placement.BEFORE
            if placement is Placement.BEFORE:
                known = True
                if consent.granted:
                    allowed.update(consent.scopes or ())
            elif consent.granted:
                (late if placement is Placement.AFTER else unplaced).update(consent.scopes or ())
        return known, allowed, late, unplaced - allowed

    def _grant(self, known: bool, allowed: set[str], late: set[str], exceeded: list[str]) -> str:
        if not known:
            said = "no consent is recorded for that client before it"
        else:
            said = (
                f"the consent recorded for that client by then grants "
                f"{', '.join(sorted(allowed)) if allowed else 'nothing'}"
            )
        granted_late = sorted(set(exceeded) & late)
        if granted_late:
            said += f"; a consent recorded after it grants {', '.join(granted_late)}"
        return said


def _granted() -> Span:
    """Build the consent screen granting the client `docs:read` and nothing else."""
    return Span(
        span_id="s1",
        kind=SpanKind.TOOL_EXECUTION,
        name="consent",
        consents=(Consent(client="client-1", granted=True, scopes=("docs:read",)),),
    )


def _used(scopes: tuple[str, ...] | None) -> Span:
    """Build the client calling the documents service with `scopes`, or without saying which."""
    return Span(
        span_id="s2",
        kind=SpanKind.TOOL_EXECUTION,
        name="docs",
        delegations=(Delegation(actor="client-1", boundary="client->docs", scopes=scopes),),
    )
