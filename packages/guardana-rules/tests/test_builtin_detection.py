"""Every built-in says what its findings state, and an invariant is never graded by a judge.

`docs/generated/detection-limits.md` prints each rule under what it declares, so a
built-in left `undeclared` is a rule the page cannot place, and a built-in calling
itself an invariant while an evaluator that is not deterministic decides its verdict
would put an opinion on the page as a fact.
"""

import importlib.resources
from pathlib import Path

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.rule import Rule, load_yaml_rules
from guardana.core.safety import Detection
from guardana.rules import provide_rules


def _optional_rules() -> list[Rule]:
    with importlib.resources.as_file(
        importlib.resources.files("guardana.rules.catalog").joinpath("optional")
    ) as directory:
        return [
            rule
            for path in sorted(Path(directory).glob("*.yaml"))
            for rule in load_yaml_rules(path)
        ]


def _built_ins() -> list[Rule]:
    return [*provide_rules(), *_optional_rules()]


def _graders(rule: Rule) -> set[str]:
    named = {evaluator_id for evaluator_id, _expectation in rule.declared_expectations()}
    if rule.meta.evaluator is not None:
        named.add(rule.meta.evaluator)
    return named


def test_the_optional_catalogue_is_part_of_what_is_checked() -> None:
    """Without this the two tests below could pass over an optional rule they never saw."""
    assert _optional_rules()


def test_no_built_in_rule_leaves_its_detection_undeclared() -> None:
    undeclared = sorted(
        rule.meta.id for rule in _built_ins() if rule.meta.detection is Detection.UNDECLARED
    )

    assert not undeclared, "declare `detection` (invariant or heuristic) on: " + ", ".join(
        undeclared
    )


def test_no_built_in_invariant_is_graded_by_an_evaluator_that_is_not_deterministic() -> None:
    """An evaluator the registry cannot resolve counts as not deterministic.

    A judge wired only from configuration is absent from the registry here, and a
    rule naming one must not pass this check because the judge was not installed.
    """
    evaluators = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)).evaluators()
    offending = sorted(
        f"{rule.meta.id} ({evaluator_id})"
        for rule in _built_ins()
        if rule.meta.detection is Detection.INVARIANT
        for evaluator_id in _graders(rule)
        if evaluator_id not in evaluators or evaluators[evaluator_id].deterministic is not True
    )

    assert not offending, "an invariant graded by opinion: " + ", ".join(offending)
