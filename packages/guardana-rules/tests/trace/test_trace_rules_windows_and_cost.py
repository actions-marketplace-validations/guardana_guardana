"""A later record inside a step's window is unplaced, and authority lookups stay linear."""

from collections.abc import Callable
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
    ToolExecution,
)
from guardana.rules.trace import (
    ConsentScopeExceededRule,
    PolicyDecisionIgnoredRule,
    SessionAsIdentityRule,
    UnapprovedSideEffectRule,
)
from guardana.rules.trace._order import Placement, placed
from trace_fixtures import findings, graded, inconclusive, span, trace_of

_T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)
_END = _T0 + timedelta(seconds=10)


def _step(started_at: datetime | None, ended_at: datetime | None) -> Span:
    return span("tool", started_at=started_at, ended_at=ended_at)


@pytest.mark.parametrize(
    ("recorded_at", "started_at", "ended_at", "expected"),
    [
        (_T0 - timedelta(seconds=1), _T0, _END, Placement.BEFORE),
        (_T0, _T0, _END, Placement.BEFORE),
        (_T0 + timedelta(seconds=5), _T0, _END, Placement.UNKNOWN),
        (_END, _T0, _END, Placement.UNKNOWN),
        (_END + timedelta(seconds=1), _T0, _END, Placement.AFTER),
        (_T0 + timedelta(seconds=5), _T0, None, Placement.UNKNOWN),
        (_T0 - timedelta(seconds=1), _T0, None, Placement.BEFORE),
        (_END + timedelta(seconds=1), None, _END, Placement.AFTER),
        (_T0 - timedelta(seconds=1), None, _END, Placement.UNKNOWN),
        (None, _T0, _END, Placement.UNKNOWN),
        (datetime(2026, 1, 5, 10, 0), _T0, _END, Placement.UNKNOWN),  # noqa: DTZ001 — on purpose
    ],
    ids=[
        "before-start",
        "at-start",
        "inside-window",
        "at-end",
        "after-end",
        "open-window",
        "before-open-window",
        "after-end-no-start",
        "before-end-no-start",
        "no-time",
        "zones-not-comparable",
    ],
)
def test_a_later_record_is_after_only_once_the_step_has_ended(
    recorded_at: datetime | None,
    started_at: datetime | None,
    ended_at: datetime | None,
    expected: Placement,
) -> None:
    assert placed(recorded_at, _step(started_at, ended_at)) is expected


def _payment_step() -> Span:
    effect = SideEffect(
        sink=SinkKind.PAYMENT,
        action="send_payment",
        status=EffectStatus.EXECUTED,
        reversible=False,
    )
    return span("tool", effects=(effect,), started_at=_T0, ended_at=_END)


def _child_approval(decided_at: datetime) -> Span:
    grant = Approval(action="send_payment", outcome=ApprovalOutcome.GRANTED, decided_at=decided_at)
    return span("approve", parent_span_id="tool", approvals=(grant,))


def test_a_grant_written_later_but_decided_inside_the_step_is_not_a_finding() -> None:
    trace = trace_of(_payment_step(), _child_approval(_T0 + timedelta(seconds=5)))

    results = graded(UnapprovedSideEffectRule(), trace)

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1


def test_control_a_grant_decided_after_the_step_ended_is_a_finding() -> None:
    trace = trace_of(_payment_step(), _child_approval(_END + timedelta(seconds=5)))

    (finding,) = findings(graded(UnapprovedSideEffectRule(), trace))

    assert "after the step ended" in finding.evidence.summary


def _scoped_hop() -> Span:
    hop = Delegation(actor="client-1", boundary="client->docs", scopes=("docs:write",))
    return span("tool", delegations=(hop,), started_at=_T0, ended_at=_END)


def _child_consent(recorded_at: datetime) -> Span:
    consent = Consent(
        client="client-1", granted=True, scopes=("docs:write",), recorded_at=recorded_at
    )
    return span("consent", parent_span_id="tool", consents=(consent,))


def test_a_consent_written_later_but_given_inside_the_step_is_not_a_finding() -> None:
    trace = trace_of(_scoped_hop(), _child_consent(_T0 + timedelta(seconds=5)))

    results = graded(ConsentScopeExceededRule(), trace)

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1


def test_control_a_consent_given_after_the_step_ended_is_a_finding() -> None:
    trace = trace_of(_scoped_hop(), _child_consent(_END + timedelta(seconds=5)))

    assert len(findings(graded(ConsentScopeExceededRule(), trace))) == 1


# A refusal and the request it refused, on the decision's own span.


_REFUSED = "transfer_funds"


def _denial(*, messages: tuple[Message, ...] = (), tool: ToolExecution | None = None) -> Span:
    decision = PolicyDecision(outcome=PolicyOutcome.DENY, action=_REFUSED, policy="payments")
    return span("s1", policy_decisions=(decision,), messages=messages, tool=tool)


def _asking(tool: str) -> Message:
    call = ContentPart(kind=PartKind.TOOL_CALL, tool_name=tool, call_id="c1")
    return Message(role=Role.ASSISTANT, parts=(call,))


def test_a_request_the_policy_refused_on_its_own_span_is_the_guardrail_working() -> None:
    trace = trace_of(_denial(messages=(_asking(_REFUSED),)))

    assert graded(PolicyDecisionIgnoredRule(), trace) == ()


def test_control_the_refused_action_executed_on_the_decisions_own_span_is_declined() -> None:
    trace = trace_of(_denial(tool=ToolExecution(name=_REFUSED)))

    results = graded(PolicyDecisionIgnoredRule(), trace)

    assert findings(results) == ()
    (decline,) = inconclusive(results)
    assert "the action itself" in decline.evidence.summary


# An attempted payment whose only grant is placed after it, or nowhere.


def _attempt(action: str) -> SideEffect:
    return SideEffect(sink=SinkKind.PAYMENT, action=action, status=EffectStatus.ATTEMPTED)


def _late_grant(span_id: str, action: str, decided_at: datetime | None) -> Span:
    grant = Approval(action=action, outcome=ApprovalOutcome.GRANTED, decided_at=decided_at)
    return span(span_id, approvals=(grant,))


@pytest.mark.parametrize(
    "decided_at", [_END + timedelta(minutes=1), None], ids=["placed-after", "unplaced"]
)
def test_an_attempted_payment_granted_only_later_is_declined_once(
    decided_at: datetime | None,
) -> None:
    trace = trace_of(
        span("s1", effects=(_attempt("pay"), _attempt("refund")), started_at=_T0, ended_at=_END),
        _late_grant("s2", "pay", decided_at),
        _late_grant("s3", "refund", decided_at),
    )

    results = graded(UnapprovedSideEffectRule(), trace)

    assert findings(results) == ()
    (decline,) = inconclusive(results)
    assert "2 consequential effect(s) attempted" in decline.evidence.summary


def test_control_an_attempted_payment_granted_beforehand_is_silent() -> None:
    trace = trace_of(
        _late_grant("s0", "pay", None),
        span("s1", effects=(_attempt("pay"),)),
    )

    assert graded(UnapprovedSideEffectRule(), trace) == ()


# A session-only step in a trace that can show no change at all.


_SESSION = Identity(session=SessionRef(id="session-1", protocol="mcp"))


def test_session_only_steps_with_only_requested_tools_are_declined() -> None:
    chat = span("s1", identity=_SESSION, messages=(_asking("update_record"),))

    results = graded(
        SessionAsIdentityRule(), trace_of(chat, records={Dimension.IDENTITY, Dimension.TOOLS})
    )

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1


def test_control_a_mutating_tool_on_a_session_only_step_is_a_finding() -> None:
    chat = span("s1", identity=_SESSION, messages=(_asking("update_record"),))
    write = span("s2", identity=_SESSION, tool=ToolExecution(name="update_record", mutates=True))

    results = graded(
        SessionAsIdentityRule(),
        trace_of(chat, write, records={Dimension.IDENTITY, Dimension.TOOLS}),
    )

    assert len(findings(results)) == 1
    assert inconclusive(results) == ()


# Cost: each effect or hop reads only the records for its own key.


def _counting() -> tuple[type[str], list[int]]:
    """Return a `str` type that counts every comparison and hash made on it."""
    count = [0]

    class Counted(str):
        __slots__ = ()

        def __eq__(self, other: object) -> bool:
            count[0] += 1
            return str.__eq__(self, other)

        def __ne__(self, other: object) -> bool:
            count[0] += 1
            return str.__ne__(self, other)

        def __hash__(self) -> int:
            count[0] += 1
            return str.__hash__(self)

    return Counted, count


_RECORDS = 1_000


def _effects_each_granted(key: Callable[[int], str]) -> list[Span]:
    return [
        span(
            f"s{index}",
            approvals=(Approval(action=key(index), outcome=ApprovalOutcome.GRANTED),),
            effects=(
                SideEffect(sink=SinkKind.PAYMENT, action=key(index), status=EffectStatus.EXECUTED),
            ),
        )
        for index in range(_RECORDS)
    ]


def test_control_the_counter_sees_the_approval_lookup() -> None:
    counted, count = _counting()
    spans = _effects_each_granted(lambda index: counted(f"pay-{index}"))[:1]

    assert graded(UnapprovedSideEffectRule(), trace_of(*spans)) == ()
    assert count[0] >= 1


def test_grading_effects_against_approvals_grows_linearly_with_the_records() -> None:
    counted, count = _counting()
    spans = _effects_each_granted(lambda index: counted(f"pay-{index}"))

    results = graded(UnapprovedSideEffectRule(), trace_of(*spans))
    if results:
        raise RuntimeError(f"every payment was granted, yet {len(results)} result(s) came back")

    assert count[0] <= 8 * _RECORDS, f"{count[0]} operations for {_RECORDS} effects"


def _hops_each_consented(key: Callable[[int], str]) -> list[Span]:
    return [
        span(
            f"s{index}",
            consents=(Consent(client=key(index), granted=True, scopes=("docs:read",)),),
            delegations=(
                Delegation(actor=key(index), boundary="client->docs", scopes=("docs:read",)),
            ),
        )
        for index in range(_RECORDS)
    ]


def test_control_the_counter_sees_the_consent_lookup() -> None:
    counted, count = _counting()
    spans = _hops_each_consented(lambda index: counted(f"client-{index}"))[:1]

    assert graded(ConsentScopeExceededRule(), trace_of(*spans)) == ()
    assert count[0] >= 1


def test_grading_hops_against_consents_grows_linearly_with_the_records() -> None:
    counted, count = _counting()
    spans = _hops_each_consented(lambda index: counted(f"client-{index}"))

    results = graded(ConsentScopeExceededRule(), trace_of(*spans))
    if results:
        raise RuntimeError(f"every hop was consented, yet {len(results)} result(s) came back")

    assert count[0] <= 8 * _RECORDS, f"{count[0]} operations for {_RECORDS} hops"
