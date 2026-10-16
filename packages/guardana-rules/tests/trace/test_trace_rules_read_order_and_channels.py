"""Authority counts once recorded, and no rule passes over a channel it cannot see."""

from datetime import UTC, datetime, timedelta

import pytest
from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    Consent,
    ContentPart,
    Delegation,
    Dimension,
    EffectStatus,
    Identity,
    Message,
    PartKind,
    PolicyDecision,
    PolicyOutcome,
    Role,
    SessionRef,
    SideEffect,
    SinkKind,
    Span,
)
from guardana.rules.trace import (
    ConsentScopeExceededRule,
    PolicyDecisionIgnoredRule,
    SessionAsIdentityRule,
    UnapprovedSideEffectRule,
)
from trace_fixtures import findings, graded, inconclusive, span, trace_of

_START = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


def _charge(started_at: datetime | None = None) -> Span:
    effect = SideEffect(sink=SinkKind.PAYMENT, action="charge_card", status=EffectStatus.EXECUTED)
    return span("s1", effects=(effect,), started_at=started_at, ended_at=started_at)


def _approval(outcome: ApprovalOutcome, decided_at: datetime | None = None) -> Span:
    return span(
        "s2", approvals=(Approval(action="charge_card", outcome=outcome, decided_at=decided_at),)
    )


@pytest.mark.parametrize(
    ("decided_at", "found", "declined"),
    [
        (_START + timedelta(minutes=5), 1, 0),
        (_START - timedelta(minutes=5), 0, 0),
        (None, 0, 1),
        (datetime(2026, 1, 5, 8, 0), 0, 1),  # noqa: DTZ001 — a clock with no zone, on purpose
    ],
    ids=["decided-after", "decided-before", "no-time", "clocks-not-comparable"],
)
def test_a_grant_recorded_after_the_payment_is_placed_by_its_own_time(
    decided_at: datetime | None, found: int, declined: int
) -> None:
    trace = trace_of(_charge(_START), _approval(ApprovalOutcome.GRANTED, decided_at))

    results = graded(UnapprovedSideEffectRule(), trace)

    assert (len(findings(results)), len(inconclusive(results))) == (found, declined)


@pytest.mark.parametrize(
    "outcome",
    [ApprovalOutcome.DENIED, ApprovalOutcome.NOT_REQUESTED, ApprovalOutcome.TIMED_OUT],
)
def test_a_refusal_recorded_after_the_payment_still_counts(outcome: ApprovalOutcome) -> None:
    trace = trace_of(_charge(), _approval(outcome))

    assert len(findings(graded(UnapprovedSideEffectRule(), trace))) == 1


def test_a_grant_in_an_earlier_span_covers_the_payment() -> None:
    grant = span("s0", approvals=(Approval(action="charge_card", outcome=ApprovalOutcome.GRANTED),))

    assert graded(UnapprovedSideEffectRule(), trace_of(grant, _charge())) == ()


def _hop(started_at: datetime | None = None) -> Span:
    hop = Delegation(actor="client-1", boundary="client->docs", scopes=("docs:read", "docs:write"))
    return span("s1", delegations=(hop,), started_at=started_at, ended_at=started_at)


def _consent(recorded_at: datetime | None = None, *, granted: bool = True) -> Span:
    consent = Consent(
        client="client-1",
        granted=granted,
        scopes=("docs:read", "docs:write"),
        recorded_at=recorded_at,
    )
    return span("s2", consents=(consent,))


@pytest.mark.parametrize(
    ("recorded_at", "found", "declined"),
    [
        (_START + timedelta(seconds=1), 1, 0),
        (_START - timedelta(seconds=1), 0, 0),
        (None, 0, 1),
    ],
    ids=["recorded-after", "recorded-before", "no-time"],
)
def test_a_consent_recorded_after_the_hop_is_placed_by_its_own_time(
    recorded_at: datetime | None, found: int, declined: int
) -> None:
    trace = trace_of(_hop(_START), _consent(recorded_at))

    results = graded(ConsentScopeExceededRule(), trace)

    assert (len(findings(results)), len(inconclusive(results))) == (found, declined)


def test_a_late_consent_is_named_in_the_finding() -> None:
    trace = trace_of(_hop(_START), _consent(_START + timedelta(seconds=1)))

    (finding,) = findings(graded(ConsentScopeExceededRule(), trace))

    assert "a consent recorded after it grants docs:read, docs:write" in finding.evidence.summary


def test_a_later_refusal_leaves_the_hop_ungranted() -> None:
    trace = trace_of(_hop(), _consent(granted=False))

    assert len(findings(graded(ConsentScopeExceededRule(), trace))) == 1


def test_the_consent_rule_needs_delegation_recorded() -> None:
    needed = {c.value for c in ConsentScopeExceededRule().meta.required_capabilities}

    assert "read_delegation" in needed


_DENIAL = span(
    "s1",
    policy_decisions=(PolicyDecision(outcome=PolicyOutcome.DENY, action="transfer_funds"),),
)


@pytest.mark.parametrize(
    ("records", "declined"),
    [
        ({Dimension.POLICY}, 1),
        ({Dimension.POLICY, Dimension.EFFECTS}, 0),
        ({Dimension.POLICY, Dimension.TOOLS}, 0),
    ],
    ids=["policy-only", "with-effects", "with-tools"],
)
def test_a_refusal_is_declined_only_where_no_action_could_have_been_recorded(
    records: set[Dimension], declined: int
) -> None:
    results = graded(PolicyDecisionIgnoredRule(), trace_of(_DENIAL, records=records))

    assert findings(results) == ()
    assert len(inconclusive(results)) == declined


def test_a_policy_only_trace_with_no_refusal_is_not_a_question() -> None:
    allow = span(
        "s1",
        policy_decisions=(PolicyDecision(outcome=PolicyOutcome.ALLOW, action="transfer_funds"),),
    )

    assert graded(PolicyDecisionIgnoredRule(), trace_of(allow, records={Dimension.POLICY})) == ()


def test_a_session_only_step_is_declined_where_no_change_could_have_been_recorded() -> None:
    bare = span("s1", identity=Identity(session=SessionRef(id="session-1", protocol="mcp")))

    results = graded(SessionAsIdentityRule(), trace_of(bare, records={Dimension.IDENTITY}))

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1


def test_a_refused_tool_requested_by_a_later_message_is_declined_never_passed() -> None:
    call = ContentPart(kind=PartKind.TOOL_CALL, tool_name="transfer_funds", call_id="c1")
    request = span("s2", messages=(Message(role=Role.ASSISTANT, parts=(call,)),))

    results = graded(PolicyDecisionIgnoredRule(), trace_of(_DENIAL, request))

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1
    assert "requested 'transfer_funds'" in inconclusive(results)[0].evidence.summary
