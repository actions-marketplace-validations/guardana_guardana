"""Write order is not time order: a span written first can still have happened later."""

from datetime import UTC, datetime, timedelta

import pytest
from guardana.core.trace import (
    AgentRef,
    Approval,
    ApprovalOutcome,
    Consent,
    CredentialKind,
    CredentialRef,
    Delegation,
    Dimension,
    EffectStatus,
    Handoff,
    Identity,
    PolicyDecision,
    PolicyOutcome,
    SessionRef,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    ToolExecution,
)
from guardana.rules.trace import (
    ConsentScopeExceededRule,
    HandoffAuthorityExpansionRule,
    IdentityDisagreementRule,
    PolicyDecisionIgnoredRule,
    SessionAsIdentityRule,
    UnapprovedSideEffectRule,
)
from trace_fixtures import findings, graded, inconclusive, span, trace_of

_T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


def _at(seconds: int) -> datetime:
    return _T0 + timedelta(seconds=seconds)


# An approval or consent written before the step, whose own clock puts it after the step.


def _payment(approvals: tuple[Approval, ...] = ()) -> Span:
    effect = SideEffect(
        sink=SinkKind.PAYMENT, action="send_payment", status=EffectStatus.EXECUTED, reversible=False
    )
    return span(
        "pay",
        parent_span_id="turn",
        approvals=approvals,
        effects=(effect,),
        started_at=_at(1),
        ended_at=_at(5),
    )


def _grant(decided_at: datetime | None) -> Approval:
    return Approval(action="send_payment", outcome=ApprovalOutcome.GRANTED, decided_at=decided_at)


def _turn(approvals: tuple[Approval, ...] = ()) -> Span:
    return span(
        "turn",
        SpanKind.AGENT_INVOCATION,
        approvals=approvals,
        started_at=_T0,
        ended_at=_at(7200),
    )


def test_a_grant_written_first_but_decided_after_the_payment_does_not_cover_it() -> None:
    trace = trace_of(_turn((_grant(_at(3600)),)), _payment())

    (finding,) = findings(graded(UnapprovedSideEffectRule(), trace))

    assert "after the step ended" in finding.evidence.summary


def test_a_grant_on_the_payments_own_span_decided_after_it_ended_does_not_cover_it() -> None:
    trace = trace_of(_payment((_grant(_at(3600)),)))

    assert len(findings(graded(UnapprovedSideEffectRule(), trace))) == 1


@pytest.mark.parametrize(
    "decided_at",
    [_at(3), _at(5), None, _at(-1)],
    ids=["inside-the-window", "at-the-end", "no-time", "before-the-start"],
)
def test_control_a_grant_on_the_payments_own_span_still_counts(decided_at: datetime | None) -> None:
    trace = trace_of(_payment((_grant(decided_at),)))

    assert graded(UnapprovedSideEffectRule(), trace) == ()


def test_control_a_parent_grant_decided_before_the_payment_still_counts() -> None:
    trace = trace_of(_turn((_grant(_T0),)), _payment())

    assert graded(UnapprovedSideEffectRule(), trace) == ()


def _hop(consents: tuple[Consent, ...] = ()) -> Span:
    hop = Delegation(actor="client-1", boundary="client->docs", scopes=("docs:write",))
    return span(
        "hop",
        parent_span_id="turn",
        consents=consents,
        delegations=(hop,),
        started_at=_at(1),
        ended_at=_at(5),
    )


def _consent(recorded_at: datetime | None) -> Consent:
    return Consent(client="client-1", granted=True, scopes=("docs:write",), recorded_at=recorded_at)


def test_a_consent_written_first_but_given_after_the_hop_does_not_cover_it() -> None:
    parent = span("turn", SpanKind.AGENT_INVOCATION, consents=(_consent(_at(3600)),))

    assert len(findings(graded(ConsentScopeExceededRule(), trace_of(parent, _hop())))) == 1


def test_a_consent_on_the_hops_own_span_given_after_it_ended_does_not_cover_it() -> None:
    trace = trace_of(_hop((_consent(_at(3600)),)))

    assert len(findings(graded(ConsentScopeExceededRule(), trace))) == 1


@pytest.mark.parametrize("recorded_at", [_at(3), None], ids=["inside-the-window", "no-time"])
def test_control_a_consent_on_the_hops_own_span_still_counts(
    recorded_at: datetime | None,
) -> None:
    assert graded(ConsentScopeExceededRule(), trace_of(_hop((_consent(recorded_at),)))) == ()


# A refused action written before the decision's span.


_POLICY_RECORDS = {Dimension.POLICY, Dimension.TOOLS}


def _transfer(span_id: str, started_at: datetime | None) -> Span:
    return span(
        span_id,
        parent_span_id="turn",
        tool=ToolExecution(name="transfer_funds"),
        started_at=started_at,
        ended_at=started_at + timedelta(seconds=1) if started_at is not None else None,
    )


def _deny(span_id: str = "turn") -> Span:
    decision = PolicyDecision(
        outcome=PolicyOutcome.DENY, action="transfer_funds", policy="funds-guard"
    )
    return span(
        span_id,
        SpanKind.AGENT_INVOCATION,
        policy_decisions=(decision,),
        started_at=_T0,
        ended_at=_at(10),
    )


def test_a_refused_action_written_first_but_run_after_the_decision_is_a_finding() -> None:
    trace = trace_of(_transfer("tool", _at(15)), _deny(), records=_POLICY_RECORDS)

    (finding,) = findings(graded(PolicyDecisionIgnoredRule(), trace))

    assert "performed it anyway" in finding.evidence.summary


@pytest.mark.parametrize("started_at", [_at(5), _T0, None], ids=["inside", "at-start", "no-time"])
def test_a_refused_action_written_first_and_not_ordered_against_the_decision_is_declined(
    started_at: datetime | None,
) -> None:
    trace = trace_of(_transfer("tool", started_at), _deny(), records=_POLICY_RECORDS)

    results = graded(PolicyDecisionIgnoredRule(), trace)

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1


def test_refused_actions_no_clock_orders_are_declined_in_one_line() -> None:
    trace = trace_of(
        _transfer("tool-1", _at(5)),
        _transfer("tool-2", _at(6)),
        _deny("turn-1"),
        _deny("turn-2"),
        records=_POLICY_RECORDS,
    )

    (decline,) = inconclusive(graded(PolicyDecisionIgnoredRule(), trace))

    assert "tool-1" in decline.evidence.summary
    assert "tool-2" in decline.evidence.summary


def test_control_a_refused_action_that_ran_before_the_decision_is_silent() -> None:
    trace = trace_of(_transfer("tool", _at(-5)), _deny(), records=_POLICY_RECORDS)

    assert graded(PolicyDecisionIgnoredRule(), trace) == ()


def test_control_a_refused_action_written_after_the_decision_is_still_a_finding() -> None:
    trace = trace_of(_deny(), _transfer("tool", _at(5)), records=_POLICY_RECORDS)

    assert len(findings(graded(PolicyDecisionIgnoredRule(), trace))) == 1


# A receiver's delegation written before the handoff span.


def _handoff() -> Span:
    return span(
        "ho",
        SpanKind.HANDOFF,
        parent_span_id="root",
        agent=AgentRef(name="A"),
        handoff=Handoff(from_agent="A", to_agent="B", carried_scopes=("docs:read",)),
        started_at=_at(1),
        ended_at=_at(30),
    )


def _admin(started_at: datetime) -> Span:
    return span(
        "work",
        parent_span_id="ho",
        agent=AgentRef(name="B"),
        delegations=(Delegation(actor="B", boundary="B->docs", scopes=("docs:admin",)),),
        started_at=started_at,
        ended_at=started_at + timedelta(seconds=1),
    )


_ROOT = span("root", SpanKind.AGENT_INVOCATION, agent=AgentRef(name="A"))


def test_a_receivers_use_written_first_but_made_after_the_handoff_is_a_finding() -> None:
    trace = trace_of(_admin(_at(40)), _handoff(), _ROOT)

    (finding,) = findings(graded(HandoffAuthorityExpansionRule(), trace))

    assert "docs:admin" in finding.evidence.summary


def test_a_receivers_use_written_first_with_no_later_actor_is_still_a_finding() -> None:
    trace = trace_of(_admin(_at(40)), _handoff())

    assert len(findings(graded(HandoffAuthorityExpansionRule(), trace))) == 1


def test_a_receivers_use_written_first_inside_the_handoff_is_declined() -> None:
    trace = trace_of(_admin(_at(2)), _handoff(), _ROOT)

    results = graded(HandoffAuthorityExpansionRule(), trace)

    assert findings(results) == ()
    (decline,) = inconclusive(results)
    assert "work" in decline.evidence.summary


def test_control_a_receivers_use_before_the_handoff_began_is_not_the_handoffs() -> None:
    trace = trace_of(_admin(_at(-5)), _handoff(), _ROOT)

    assert graded(HandoffAuthorityExpansionRule(), trace) == ()


def test_control_a_receivers_use_written_after_the_handoff_is_still_a_finding() -> None:
    trace = trace_of(_ROOT, _handoff(), _admin(_at(2)))

    assert len(findings(graded(HandoffAuthorityExpansionRule(), trace))) == 1


# A session-only step whose mutation is unknown, beside a span that states one.


_SESSION = Identity(session=SessionRef(id="sess-1", protocol="mcp"))
_IDENTITY_RECORDS = {Dimension.IDENTITY, Dimension.TOOLS}


def _delete_user(mutates: bool | None) -> Span:
    return span("s1", identity=_SESSION, tool=ToolExecution(name="delete_user", mutates=mutates))


_SEARCH = span("s2", tool=ToolExecution(name="search", mutates=False))


def test_a_session_only_step_of_unknown_mutation_beside_a_read_is_declined() -> None:
    trace = trace_of(_delete_user(None), _SEARCH, records=_IDENTITY_RECORDS)

    results = graded(SessionAsIdentityRule(), trace)

    assert findings(results) == ()
    (decline,) = inconclusive(results)
    assert "s1" in decline.evidence.summary


def test_session_only_steps_of_unknown_mutation_are_declined_in_one_line() -> None:
    second = span("s3", identity=_SESSION, tool=ToolExecution(name="drop_table"))
    trace = trace_of(_delete_user(None), _SEARCH, second, records=_IDENTITY_RECORDS)

    assert len(inconclusive(graded(SessionAsIdentityRule(), trace))) == 1


def test_control_a_session_only_mutating_step_beside_a_read_is_a_finding() -> None:
    trace = trace_of(_delete_user(True), _SEARCH, records=_IDENTITY_RECORDS)

    results = graded(SessionAsIdentityRule(), trace)

    assert len(findings(results)) == 1
    assert inconclusive(results) == ()


def test_control_a_session_only_read_beside_another_read_is_silent() -> None:
    trace = trace_of(_delete_user(False), _SEARCH, records=_IDENTITY_RECORDS)

    assert graded(SessionAsIdentityRule(), trace) == ()


def test_control_a_lone_session_only_step_of_unknown_mutation_is_declined_once() -> None:
    trace = trace_of(_delete_user(None), records=_IDENTITY_RECORDS)

    assert len(inconclusive(graded(SessionAsIdentityRule(), trace))) == 1


# A credential whose kind does not say it is never audience-bound.


@pytest.mark.parametrize(
    ("kind", "declined"),
    [
        (CredentialKind.OTHER, 1),
        (CredentialKind.BEARER, 1),
        (CredentialKind.API_KEY, 0),
        (CredentialKind.BASIC, 0),
        (CredentialKind.MTLS, 0),
    ],
    ids=["other", "bearer", "api-key", "basic", "mtls"],
)
def test_only_a_credential_stated_as_never_audience_bound_is_left_out(
    kind: CredentialKind, declined: int
) -> None:
    identity = Identity(
        credential=CredentialRef(kind=kind, digest="sha256:abc"),
        claimed_resource="https://billing.invalid",
    )

    results = graded(IdentityDisagreementRule(), trace_of(span("s1", identity=identity)))

    assert findings(results) == ()
    assert len(inconclusive(results)) == declined
