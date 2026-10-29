"""Every built-in rule proves it can find, stay silent and decline, on samples of its own.

`guardana rule test` asks a third party to sample every rule they ship, and a project that
exempted itself would be asking them to clear a bar it had not. A rule that can never decline
honestly is listed in `_EXEMPT` with the reason, and nowhere else.
"""

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.rule.verify import verify_rule
from guardana.rules import provide_rules

_EXEMPT: dict[str, str] = {}
"""Built-in rules that can never be prevented from establishing their claim, each with why."""


def _sampled() -> tuple[list[str], list[str]]:
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    ctx = RuleContext(evaluators=registry.evaluators())
    proven: list[str] = []
    unsampled: list[str] = []
    for rule in provide_rules():
        (unsampled if verify_rule(rule, ctx).gaps else proven).append(rule.meta.id)
    return proven, unsampled


def test_every_built_in_rule_not_exempt_carries_all_three_samples() -> None:
    proven, unsampled = _sampled()

    missing = sorted(set(unsampled) - set(_EXEMPT))
    assert not missing, (
        f"built-in rules without a finding, a clean and an inconclusive sample: {missing}"
    )
    assert len(proven) == len(provide_rules()) - len(_EXEMPT)


def test_every_exemption_names_a_shipped_unsampled_rule_and_a_reason() -> None:
    _proven, unsampled = _sampled()

    stale = sorted(rule_id for rule_id in _EXEMPT if rule_id not in unsampled)
    assert not stale, f"exempt rules that ship all three samples or no longer exist: {stale}"
    assert all(reason.strip() for reason in _EXEMPT.values())


def test_every_fully_sampled_rule_actually_classifies_its_own_samples() -> None:
    """The ratchet counts rules with three outcomes declared; this checks they pass.

    Separate on purpose: a rule could declare all three fixtures and get them wrong,
    and a coverage count that rose on a broken rule would be measuring paperwork.
    """
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    ctx = RuleContext(evaluators=registry.evaluators())

    wrong = [
        f"{rule.meta.id}: {result.fixture} — {result.detail}"
        for rule in provide_rules()
        for result in verify_rule(rule, ctx).results
        if result.verdict is not None and result.verdict != "passed"
    ]

    assert not wrong, "\n  ".join(wrong)
