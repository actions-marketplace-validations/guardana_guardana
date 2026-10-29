"""Every supply-chain rule classifies its own finding, clean and inconclusive samples."""

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.fixture import DEMANDED_OUTCOMES
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.rules import provide_rules

_FAMILY = "guardana.supply_chain."
_RULES = [rule for rule in provide_rules() if rule.meta.id.startswith(_FAMILY)]


def test_the_family_is_not_empty() -> None:
    assert _RULES


@pytest.mark.parametrize("rule", _RULES, ids=lambda rule: rule.meta.id.removeprefix(_FAMILY))
def test_the_rule_is_proven_by_its_own_samples(rule: Rule) -> None:
    verified = verify_rule(rule, RuleContext())

    assert verified.is_proven, verified
    passed = {
        result.expected for result in verified.results if result.verdict is FixtureVerdict.PASSED
    }
    assert passed >= set(DEMANDED_OUTCOMES)


@pytest.mark.parametrize("rule", _RULES, ids=lambda rule: rule.meta.id.removeprefix(_FAMILY))
def test_each_sample_builds_a_fresh_tree(rule: Rule) -> None:
    first, second = tuple(rule.fixtures()), tuple(rule.fixtures())

    assert [f.name for f in first] == [f.name for f in second]
    assert not {f.target.ref for f in first} & {f.target.ref for f in second}
