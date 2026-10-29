"""A seeded check reads an application's declines from what was asked as whom.

A pair's own ask declined as a refusal carries no marker, so with both controls answered
it is clean; declined as ungraded it is not measured, and a pair never answered is open.
A declined control is a control that did not answer: the seed was not reached. The
poisoned document's question is its own control, so a decline there is never clean.
"""

from collections.abc import Callable, Sequence

import pytest
from guardana.core.assessment import AssessmentStatus, UnmeasuredReason
from guardana.core.fixtures import Fixtures, SeededItem
from guardana.core.report import Finding
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ChatMessage, Decline, DeclineReading, RequestDeclined
from guardana.core.testing.seeded import SeededApplication, seeded_target, tenant_key
from guardana.rules.seeded import CrossTenantAnswerRule, PoisonedDocumentRule
from guardana.rules.seeded._samples import sample_fixtures

_REFUSED = Decline("tenant_guard", DeclineReading.REFUSAL, 400)
_UNGRADED = Decline("input_rejected", DeclineReading.UNGRADED, 413)

Rule = Callable[[str | None, SeededItem], Decline | None]


def _guarded(fixtures: Fixtures, declines: Rule) -> SeededApplication:
    """The sample application behind a guard that declines what `declines` names."""
    tenants = {tenant_key(name): name for name in fixtures.tenant_names}
    items = fixtures.items

    class _Guarded(SeededApplication):
        def send(
            self,
            base_url: str,
            model: str,
            messages: Sequence[ChatMessage],
            api_key: str | None,
        ) -> str:
            question = messages[-1].content
            item = next(i for i in items if i.question == question)
            declined = declines(None if api_key is None else tenants.get(api_key), item)
            if declined is not None:
                raise RequestDeclined(declined)
            return super().send(base_url, model, messages, api_key)

    return _Guarded(fixtures)


def _run(
    rule: CrossTenantAnswerRule | PoisonedDocumentRule, declines: Rule
) -> tuple[list[Finding], RuleContext]:
    fixtures = sample_fixtures()
    ctx = RuleContext()
    target = seeded_target(fixtures, _guarded(fixtures, declines))
    return list(rule.run(target, ctx)), ctx


def _probe(decline: Decline) -> Rule:
    """Decline every question asked as a tenant that does not own its item."""
    return lambda tenant, item: decline if tenant != item.owner else None


def test_a_cross_tenant_ask_refused_by_the_application_is_clean_when_both_controls_answered() -> (
    None
):
    findings, ctx = _run(CrossTenantAnswerRule(), _probe(_REFUSED))

    assert findings == []
    assert not ctx.shortfalls()
    recorded = ctx.recorded()
    assert len(recorded) == 5
    assert all(a.passed is True for a in recorded)
    assert all(a.tags == ("declined:tenant_guard",) for a in recorded)
    assert all(
        "declined by the application: tenant_guard (HTTP 400)" in a.rationale for a in recorded
    )


def test_a_cross_tenant_ask_declined_as_ungraded_is_never_clean() -> None:
    findings, ctx = _run(CrossTenantAnswerRule(), _probe(_UNGRADED))

    recorded = ctx.recorded()
    assert {a.status for a in recorded} == {AssessmentStatus.INCONCLUSIVE}
    assert {a.reason for a in recorded} == {UnmeasuredReason.TARGET_DECLINED}
    assert all(a.tags == ("declined:input_rejected",) for a in recorded)
    assert len(findings) == 5
    assert all(f.verdict and f.verdict.outcome == "inconclusive" for f in findings)
    assert {g.kind for g in ctx.shortfalls()} == {ShortfallKind.SEED_NOT_REACHED}
    assert all("input_rejected (HTTP 413)" in g.detail for g in ctx.shortfalls())


def test_a_declined_control_is_a_seed_not_reached_never_a_clean_pair() -> None:
    def own_documents(tenant: str | None, item: SeededItem) -> Decline | None:
        return _REFUSED if tenant == item.owner and item.owner == "acme" else None

    findings, ctx = _run(CrossTenantAnswerRule(), own_documents)

    assert ctx.shortfalls()
    assert {g.kind for g in ctx.shortfalls()} == {ShortfallKind.SEED_NOT_REACHED}
    assert any(f.verdict and f.verdict.outcome == "inconclusive" for f in findings)
    unreached = {g.name for g in ctx.shortfalls()}
    acme_items = {i.label for i in sample_fixtures().items if i.owner == "acme"}
    assert all(
        name.endswith("asked as acme") or any(label in name for label in acme_items)
        for name in unreached
    )


@pytest.mark.parametrize("decline", [_REFUSED, _UNGRADED], ids=["refusal", "ungraded"])
def test_a_declined_poisoned_question_did_not_reach_the_document_under_either_reading(
    decline: Decline,
) -> None:
    def everything(_tenant: str | None, _item: SeededItem) -> Decline:
        return decline

    findings, ctx = _run(PoisonedDocumentRule(), everything)

    (assessment,) = ctx.recorded()
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.reason is UnmeasuredReason.TARGET_DECLINED
    assert assessment.tags == (decline.tag,)
    assert [f.verdict.outcome for f in findings if f.verdict] == ["inconclusive"]
    assert [g.kind for g in ctx.shortfalls()] == [ShortfallKind.SEED_NOT_REACHED]
    assert decline.described in ctx.shortfalls()[0].detail
