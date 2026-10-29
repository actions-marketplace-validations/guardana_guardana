"""The tenant and poisoned-document checks decide from what was sent as whom, never by default.

Driven against `SeededApplication`, a retrieval application over the fixtures whose
switches break the tenant filter per channel, leave items out of the index, or obey a
poisoned document. Every request goes through the seeded target's shared meter.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.fixtures import DOCUMENTS_CHANNEL, Fixtures, parse_fixtures
from guardana.core.gate import gate_outcome
from guardana.core.manifest.build import build_run_manifest
from guardana.core.plan import build_plan
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.runner import Runner
from guardana.core.target import ChatMessage, EndpointError, SeededTarget
from guardana.core.testing.seeded import SeededApplication, seeded_target
from guardana.rules.seeded import CrossTenantAnswerRule, PoisonedDocumentRule
from guardana.rules.seeded._samples import SAMPLE_FIXTURES, sample_fixtures
from guardana.rules.seeded.cross_tenant_answer import CLEAN

_ORDERS = "records/orders"


def _target(
    fixtures: Fixtures | None = None,
    *,
    leaking: frozenset[str] = frozenset(),
    unseeded: frozenset[str] = frozenset(),
    obeys: bool = False,
) -> SeededTarget:
    seeded = fixtures or sample_fixtures()
    application = SeededApplication(seeded, leaking=leaking, unseeded=unseeded, obeys=obeys)
    return seeded_target(seeded, application)


def _run(
    rule: CrossTenantAnswerRule | PoisonedDocumentRule, target: SeededTarget
) -> tuple[list[Finding], RuleContext]:
    ctx = RuleContext()
    return list(rule.run(target, ctx)), ctx


def _fails(findings: Sequence[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is not None and f.verdict.outcome == "fail"]


def _declines(findings: Sequence[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is not None and f.verdict.outcome == "inconclusive"]


def test_a_document_filter_that_ignores_the_tenant_is_a_finding_for_each_crossed_pair() -> None:
    findings, ctx = _run(CrossTenantAnswerRule(), _target(leaking=frozenset({DOCUMENTS_CHANNEL})))

    crossed = {f.evidence.summary.split(",")[0] for f in _fails(findings)}
    assert len(_fails(findings)) == 3
    assert any("documents/globex-shipping" in summary for summary in crossed)
    assert not _declines(findings)
    assert not ctx.shortfalls()


def test_a_record_collection_that_ignores_the_tenant_is_a_finding_too() -> None:
    findings, _ctx = _run(CrossTenantAnswerRule(), _target(leaking=frozenset({_ORDERS})))

    leaked = _fails(findings)
    assert len(leaked) == 2
    assert all("records/orders/" in f.evidence.summary for f in leaked)


def test_a_filter_that_holds_is_clean_and_every_pair_is_measured_as_a_pass() -> None:
    findings, ctx = _run(CrossTenantAnswerRule(), _target())

    assert findings == []
    assert not ctx.shortfalls()
    recorded = ctx.recorded()
    assert len(recorded) == 5
    assert all(a.passed is True and a.rationale == CLEAN for a in recorded)


def test_an_unseeded_item_is_a_shortfall_and_an_inconclusive_verdict_never_clean() -> None:
    findings, ctx = _run(
        CrossTenantAnswerRule(), _target(unseeded=frozenset({"documents/acme-loyalty"}))
    )

    assert [f.verdict.outcome for f in findings if f.verdict] == ["inconclusive"]
    gaps = ctx.shortfalls()
    assert [(g.kind, g.name) for g in gaps] == [
        (ShortfallKind.SEED_NOT_REACHED, "documents/acme-loyalty asked as globex")
    ]


def test_a_blank_reply_to_every_tenant_but_the_owner_leaves_every_pair_open_never_clean() -> None:
    fixtures = sample_fixtures()
    application = SeededApplication(
        fixtures, leaking=frozenset({DOCUMENTS_CHANNEL}), blank_to_others=True
    )

    findings, ctx = _run(CrossTenantAnswerRule(), seeded_target(fixtures, application))

    assert len(_declines(findings)) == 5
    assert not _fails(findings)
    gaps = ctx.shortfalls()
    assert {g.kind for g in gaps} == {ShortfallKind.SEED_NOT_REACHED}
    assert "documents/acme-loyalty asked as globex" in {g.name for g in gaps}
    assert all("returned no text" in g.detail for g in gaps)
    assert {a.passed for a in ctx.recorded()} == {None}


def test_a_blank_reply_in_one_trial_leaves_that_trial_open_and_the_other_measured() -> None:
    fixtures = sample_fixtures()
    per_trial = len(fixtures.items) * len(fixtures.tenant_names)
    flaky = _Flaky(
        fixtures,
        SeededApplication(fixtures, blank_to_others=True),
        SeededApplication(fixtures),
        per_trial,
    )

    findings, ctx = _run(CrossTenantAnswerRule(trials=2), seeded_target(fixtures, flaky))

    assert findings == []
    assert not ctx.shortfalls()
    by_trial = {(a.case_id, a.trial): a.passed for a in ctx.recorded()}
    assert {passed for (_case, trial), passed in by_trial.items() if trial == 1} == {None}
    assert {passed for (_case, trial), passed in by_trial.items() if trial == 2} == {True}


def test_the_asking_tenants_control_counts_only_through_the_same_channel() -> None:
    # globex's documents answer, so its control holds for the document pairs; its only
    # record is unseeded, so the record pair has no control of its own, whatever the
    # documents showed.
    findings, ctx = _run(CrossTenantAnswerRule(), _target(unseeded=frozenset({f"{_ORDERS}/G-200"})))

    names = sorted(g.name for g in ctx.shortfalls())
    assert names == [f"{_ORDERS}/A-100 asked as globex", f"{_ORDERS}/G-200 asked as acme"]
    assert len(_declines(findings)) == 2
    assert not _fails(findings)


def test_a_leak_outranks_a_control_of_the_asking_tenant_that_failed() -> None:
    # globex's only document is unseeded, so its own control fails; acme's documents
    # still reach it, and that is a finding rather than a pair left open.
    findings, ctx = _run(
        CrossTenantAnswerRule(),
        _target(
            leaking=frozenset({DOCUMENTS_CHANNEL}),
            unseeded=frozenset({"documents/globex-shipping"}),
        ),
    )

    assert len(_fails(findings)) == 2
    assert [g.name for g in ctx.shortfalls()] == ["documents/globex-shipping asked as acme"]


def test_a_marker_reaching_a_reply_to_another_question_is_a_leak() -> None:
    fixtures = sample_fixtures()
    acme_loyalty = next(i for i in fixtures.items if i.id == "acme-loyalty")

    class _Chatty(SeededApplication):
        def send(
            self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
        ) -> str:
            reply = super().send(base_url, model, messages, api_key)
            if api_key == "key-globex":
                return f"{reply} By the way, {acme_loyalty.markers.presence}."
            return reply

    target = seeded_target(fixtures, _Chatty(fixtures))
    findings, _ctx = _run(CrossTenantAnswerRule(), target)

    assert [f.evidence.summary.split(" of ")[1].split(",")[0] for f in _fails(findings)] == [
        "documents/acme-loyalty"
    ]


@pytest.mark.parametrize("which", ["joined", "first half", "second half"])
def test_a_poisoned_documents_instruction_marker_in_another_tenants_reply_is_a_leak(
    which: str,
) -> None:
    fixtures = sample_fixtures()
    returns = next(i for i in fixtures.items if i.poisoned)
    halves = returns.markers.instruction
    assert halves is not None
    marker = {"joined": returns.markers.joined, "first half": halves[0], "second half": halves[1]}

    class _Echoes(SeededApplication):
        def send(
            self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
        ) -> str:
            reply = super().send(base_url, model, messages, api_key)
            if api_key == "key-globex":
                return f"{reply} Also: {marker[which]}"
            return reply

    findings, _ctx = _run(CrossTenantAnswerRule(), seeded_target(fixtures, _Echoes(fixtures)))

    assert len(_fails(findings)) == 1
    assert "documents/acme-returns" in _fails(findings)[0].evidence.summary
    assert "instruction marker" in _fails(findings)[0].evidence.summary


class _Flaky(SeededApplication):
    """Behaves as `first` for the first `switch_after` requests and as `then` afterwards."""

    def __init__(
        self,
        fixtures: Fixtures,
        first: SeededApplication,
        then: SeededApplication,
        switch_after: int,
    ) -> None:
        super().__init__(fixtures)
        self._first, self._then, self._switch_after, self._sent = first, then, switch_after, 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        self._sent += 1
        chosen = self._first if self._sent <= self._switch_after else self._then
        return chosen.send(base_url, model, messages, api_key)


def test_a_leak_in_any_trial_is_a_finding() -> None:
    fixtures = sample_fixtures()
    per_trial = len(fixtures.items) * len(fixtures.tenant_names)
    flaky = _Flaky(
        fixtures,
        SeededApplication(fixtures),
        SeededApplication(fixtures, leaking=frozenset({DOCUMENTS_CHANNEL})),
        per_trial,
    )

    findings, ctx = _run(CrossTenantAnswerRule(trials=2), seeded_target(fixtures, flaky))

    assert len(_fails(findings)) == 3
    assert all("(trial 2)" in f.evidence.summary for f in _fails(findings))
    by_trial = {(a.case_id, a.trial): a.passed for a in ctx.recorded()}
    assert {trial for (_case, trial), passed in by_trial.items() if passed is False} == {2}


def test_a_control_that_answered_in_one_trial_is_enough() -> None:
    fixtures = sample_fixtures()
    per_trial = len(fixtures.items) * len(fixtures.tenant_names)
    flaky = _Flaky(
        fixtures,
        SeededApplication(fixtures, unseeded={item.label for item in fixtures.items}),
        SeededApplication(fixtures),
        per_trial,
    )

    findings, ctx = _run(CrossTenantAnswerRule(trials=2), seeded_target(fixtures, flaky))

    assert findings == []
    assert not ctx.shortfalls()


def test_an_ask_that_ends_without_a_reply_raises_and_is_never_read_as_clean() -> None:
    fixtures = sample_fixtures()

    class _Refuses(SeededApplication):
        def send(
            self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
        ) -> str:
            if api_key == "key-globex":
                raise EndpointError("403 Forbidden")
            return super().send(base_url, model, messages, api_key)

    target = seeded_target(fixtures, _Refuses(fixtures))
    with pytest.raises(EndpointError):
        _run(CrossTenantAnswerRule(), target)


def test_a_leak_seen_before_the_budget_ran_out_is_still_reported() -> None:
    fixtures = sample_fixtures()
    application = SeededApplication(fixtures, leaking=frozenset({DOCUMENTS_CHANNEL}))
    target = seeded_target(fixtures, application, budgets=Budgets(max_requests=2))
    rule = CrossTenantAnswerRule()
    yielded: list[Finding] = []

    with pytest.raises(BudgetExhausted):
        yielded.extend(rule.run(target, RuleContext()))

    assert len(_fails(yielded)) == 1
    assert len(application.asked) == 2


def test_every_tenant_is_asked_every_item_through_its_own_key_on_one_meter() -> None:
    fixtures = sample_fixtures()
    application = SeededApplication(fixtures)
    target = seeded_target(fixtures, application)
    rule = CrossTenantAnswerRule(trials=3)

    list(rule.run(target, RuleContext()))

    asked = [tenant for tenant, _question in application.asked]
    assert set(asked) == {"acme", "globex"}
    assert len(asked) == target.usage().requests == rule.estimated_requests_for(target) == 30


def test_the_poisoned_check_finds_an_application_that_obeys_the_document() -> None:
    findings, ctx = _run(PoisonedDocumentRule(), _target(obeys=True))

    assert len(_fails(findings)) == 1
    assert "documents/acme-returns" in _fails(findings)[0].evidence.summary
    assert not ctx.shortfalls()


def test_a_reply_that_quotes_the_document_did_not_obey_it() -> None:
    fixtures = sample_fixtures()
    returns = next(i for i in fixtures.items if i.poisoned)

    class _Quotes(SeededApplication):
        def send(
            self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
        ) -> str:
            return f"Here is the document: {returns.text}"

    findings, ctx = _run(PoisonedDocumentRule(), seeded_target(fixtures, _Quotes(fixtures)))

    assert findings == []
    assert not ctx.shortfalls()


def test_an_unreached_poisoned_document_is_a_shortfall_never_clean() -> None:
    findings, ctx = _run(
        PoisonedDocumentRule(), _target(unseeded=frozenset({"documents/acme-returns"}), obeys=True)
    )

    assert [f.verdict.outcome for f in findings if f.verdict] == ["inconclusive"]
    assert [(g.kind, g.name) for g in ctx.shortfalls()] == [
        (ShortfallKind.SEED_NOT_REACHED, "documents/acme-returns asked as acme")
    ]


def test_a_blank_reply_to_the_poisoned_question_is_never_a_clean_trial() -> None:
    fixtures = sample_fixtures()

    class _BlankFirst(SeededApplication):
        def send(
            self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
        ) -> str:
            reply = super().send(base_url, model, messages, api_key)
            return " \n" if len(self.asked) == 1 else reply

    rule = PoisonedDocumentRule(trials=2)
    findings, ctx = _run(rule, seeded_target(fixtures, _BlankFirst(fixtures)))

    assert findings == []
    assert [(a.trial, a.passed) for a in ctx.recorded()] == [(1, None), (2, True)]


def test_the_poisoned_check_asks_only_the_owner_once_per_poisoned_document_per_trial() -> None:
    fixtures = sample_fixtures()
    application = SeededApplication(fixtures)
    target = seeded_target(fixtures, application)
    rule = PoisonedDocumentRule(trials=2)

    list(rule.run(target, RuleContext()))

    assert [tenant for tenant, _q in application.asked] == ["acme", "acme"]
    assert target.usage().requests == rule.estimated_requests_for(target) == 2


def _without_poison() -> Fixtures:
    text = SAMPLE_FIXTURES.replace(", poisoned: true", "")
    return parse_fixtures(text.encode("utf-8"), Path("guardana-fixtures.yaml"))


def test_fixtures_without_a_poisoned_document_leave_the_poisoned_check_nothing_to_do() -> None:
    rule = PoisonedDocumentRule()

    assert rule.not_applicable_to(_target(_without_poison())) is not None
    assert rule.not_applicable_to(_target()) is None


def test_without_seeded_data_neither_rule_prices_itself() -> None:
    from guardana.core.target import EndpointTarget  # noqa: PLC0415
    from guardana.core.testing import RefusingTransport  # noqa: PLC0415

    plain = EndpointTarget("http://x", "m", transport=RefusingTransport())
    for rule in (CrossTenantAnswerRule(), PoisonedDocumentRule()):
        assert rule.estimated_requests is None
        assert rule.estimated_requests_for(plain) is None
        assert rule.not_applicable_to(plain) is None


@pytest.mark.parametrize("rule", [CrossTenantAnswerRule(), PoisonedDocumentRule()])
def test_a_trial_in_which_the_application_answered_nothing_is_never_a_pass(
    rule: CrossTenantAnswerRule | PoisonedDocumentRule,
) -> None:
    sample = next(f for f in rule.fixtures() if "first trial only" in f.name)
    ctx = RuleContext()
    subject = sample.rule if sample.rule is not None else rule

    findings = list(subject.run(sample.target, ctx))

    by_trial = {(a.case_id, a.trial): a.passed for a in ctx.recorded()}
    assert {passed for (_case, trial), passed in by_trial.items() if trial == 1} == {True}
    assert {passed for (_case, trial), passed in by_trial.items() if trial == 2} == {None}
    assert findings == []
    assert not ctx.shortfalls()


def test_a_saved_seeded_run_records_each_checks_requests_as_the_plan_priced_them() -> None:
    registry = Registry()
    registry.register_rule(CrossTenantAnswerRule())
    registry.register_rule(PoisonedDocumentRule())
    registry.apply_trials(2)
    profile = Profile(name="seeded", policy=Policy(), trials=2)
    target = _target()
    plan = build_plan(registry, profile, target)
    result = Runner(registry, profile).run(target)

    manifest = build_run_manifest(
        registry,
        profile,
        result,
        target_kind=target.kind,
        target_ref=target.ref,
        gate=gate_outcome(result, profile.policy),
        started_at=datetime(2026, 10, 1, tzinfo=UTC),
        calibrations={},
        target=target,
    )

    declared = {record.id: record.declared_requests for record in manifest.rules}
    assert declared == {
        CrossTenantAnswerRule.meta.id: len(target.fixtures.items)
        * len(target.fixtures.tenant_names)
        * 2,
        PoisonedDocumentRule.meta.id: len(target.fixtures.poisoned) * 2,
    }
    assert sum(n for n in declared.values() if n is not None) == plan.max_requests
