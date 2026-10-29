"""Every built-in security rule names the public framework entry it answers to.

A team's own quality suite may leave `taxonomy` empty; a rule shipped here may not,
because the mapping is what makes its finding answerable in someone else's audit.
That holds for every YAML the package ships, including the opt-in ones no default
run loads.
"""

import importlib.resources
from collections.abc import Iterator
from importlib.resources.abc import Traversable

from guardana.core.rule import Rule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.rules import provide_rules


def _yaml_files(directory: Traversable, prefix: str = "") -> Iterator[tuple[str, Traversable]]:
    for entry in sorted(directory.iterdir(), key=lambda e: e.name):
        name = f"{prefix}{entry.name}"
        if entry.is_dir():
            yield from _yaml_files(entry, f"{name}/")
        elif entry.name.endswith(".yaml"):
            yield name, entry


def _shipped_catalog() -> dict[str, list[Rule]]:
    """Every rule in every YAML under the package's catalog, by the file it came from."""
    loaded: dict[str, list[Rule]] = {}
    for name, entry in _yaml_files(importlib.resources.files("guardana.rules.catalog")):
        with importlib.resources.as_file(entry) as path:
            loaded[name] = load_yaml_rules(path)
    return loaded


def test_every_built_in_rule_maps_to_a_public_framework() -> None:
    rules = provide_rules()
    unmapped = sorted(rule.meta.id for rule in rules if not rule.meta.taxonomy)

    assert rules
    assert unmapped == []


def test_every_rule_the_catalog_ships_maps_to_a_public_framework() -> None:
    catalog = _shipped_catalog()
    unmapped = sorted(
        rule.meta.id for rules in catalog.values() for rule in rules if not rule.meta.taxonomy
    )

    assert any(name.startswith("optional/") for name in catalog), sorted(catalog)
    assert all(catalog.values()), sorted(name for name, rules in catalog.items() if not rules)
    assert unmapped == []
