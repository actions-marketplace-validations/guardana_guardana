"""Every trace rule declares a finding, a clean and an inconclusive sample, and classifies them."""

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.fixture import DEMANDED_OUTCOMES, FixtureOutcome
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.core.target import TraceTarget
from guardana.rules.trace import (
    ConsentScopeExceededRule,
    CredentialPassthroughRule,
    CrossTenantRetrievalRule,
    HandoffAuthorityExpansionRule,
    IdentityDisagreementRule,
    PolicyDecisionIgnoredRule,
    SecretInToolArgumentRule,
    SessionAsIdentityRule,
    UnapprovedSideEffectRule,
)

_RULES = (
    ConsentScopeExceededRule(),
    CredentialPassthroughRule(),
    CrossTenantRetrievalRule(),
    HandoffAuthorityExpansionRule(),
    IdentityDisagreementRule(),
    PolicyDecisionIgnoredRule(),
    SecretInToolArgumentRule(),
    SessionAsIdentityRule(),
    UnapprovedSideEffectRule(),
)


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.meta.id)
def test_every_trace_rule_proves_all_three_outcomes(rule: Rule) -> None:
    verification = verify_rule(rule)

    assert verification.gaps == ()
    wrong = [r for r in verification.results if r.verdict is not FixtureVerdict.PASSED]
    assert wrong == []
    assert {r.expected for r in verification.results} >= set(DEMANDED_OUTCOMES)


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.meta.id)
def test_every_trace_sample_is_a_trace_the_rule_can_run_on(rule: Rule) -> None:
    """A sample over a trace missing a needed dimension would never reach the rule in a run."""
    fixtures = tuple(rule.fixtures())
    assert fixtures
    for fixture in fixtures:
        assert isinstance(fixture.target, TraceTarget)
        assert rule.meta.required_capabilities <= fixture.target.capabilities()


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.meta.id)
def test_a_trace_rule_builds_a_fresh_target_each_time_it_is_asked(rule: Rule) -> None:
    first = {f.name: f.target for f in rule.fixtures()}
    second = {f.name: f.target for f in rule.fixtures()}

    assert first
    assert first.keys() == second.keys()
    assert all(first[name] is not second[name] for name in first)


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.meta.id)
def test_an_inconclusive_trace_sample_declines_with_a_reason(rule: Rule) -> None:
    """The decline names what it could not establish, so it is never a silent pass."""
    declining = [f for f in rule.fixtures() if f.outcome is FixtureOutcome.INCONCLUSIVE]
    assert declining
    for fixture in declining:
        results = list(rule.run(fixture.target, RuleContext()))
        assert results
        assert all(r.verdict is not None and r.verdict.outcome == "inconclusive" for r in results)
        assert all(r.evidence.summary for r in results)
