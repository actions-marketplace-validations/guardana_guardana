"""A third party must be able to map rules to a framework we have never heard of.

Mapping is mandatory for a rule, so a closed list of frameworks is a wall in front
of the one field every rule has to fill in. Registration goes through an installed
package rather than a string in a YAML file, which is why the typo gate on
`taxonomy:` survives it.
"""

from collections.abc import Callable, Iterator
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

import pytest
from guardana.core.manifest.build import _coverage
from guardana.core.pack.lock import catalogue_digest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.rule import load_yaml_rules
from guardana.core.rule.errors import RuleLoadError
from guardana.core.taxonomy import (
    TaxonomyError,
    TaxonomyRef,
    catalogs,
    extensions,
    register,
    register_all,
    resolve,
)
from guardana.core.taxonomy._builtin import index as _taxonomy_registry

_ACME = TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")

_RULE = """\
id: acme.prompt.local
title: Local check
severity: high
target_kind: endpoint
evaluator: keyword
requires: [chat]
taxonomy: [ACME-14]
prompts: ["hello"]
"""


@pytest.fixture
def forget_acme() -> Iterator[None]:
    yield
    _taxonomy_registry.forget("ACME-14")


def test_a_registered_framework_can_be_named_by_a_yaml_rule(
    forget_acme: None, tmp_path: Path
) -> None:
    path = tmp_path / "acme.yaml"
    path.write_text(_RULE, encoding="utf-8")

    with pytest.raises(RuleLoadError, match="ACME-14"):
        load_yaml_rules(path)

    register(_ACME)
    (rule,) = load_yaml_rules(path)
    assert rule.meta.taxonomy == (_ACME,)


def test_registering_the_same_ref_twice_is_fine(forget_acme: None) -> None:
    # `Registry.discover()` runs once per command and many times per test session;
    # a pack that registered successfully must not look broken the second time.
    register(_ACME)
    register(TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control"))
    assert resolve("ACME-14") == _ACME


def test_a_conflicting_redefinition_is_refused(forget_acme: None) -> None:
    register(_ACME)
    with pytest.raises(TaxonomyError, match="ACME-14"):
        register(TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Something else entirely"))


def test_registering_a_set_that_fails_part_way_leaves_none_of_it_behind(
    forget_acme: None,
) -> None:
    clash = TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Not prompt injection at all")

    with pytest.raises(TaxonomyError, match="LLM01"):
        register_all([_ACME, clash])

    assert resolve("ACME-14") is None
    assert resolve("LLM01:2025") is not None


def test_registering_a_set_keeps_what_was_known_before_it(forget_acme: None) -> None:
    register(_ACME)
    clash = TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Not prompt injection at all")

    with pytest.raises(TaxonomyError):
        register_all([_ACME, clash])

    assert resolve("ACME-14") == _ACME


def test_discovery_registers_a_providers_refs(
    forget_acme: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _with_taxonomy_provider(monkeypatch, lambda: [_ACME])
    Registry.discover(PluginTrust(mode=PluginMode.ALL))
    assert resolve("ACME-14") == _ACME


def test_a_provider_redefining_a_builtin_id_is_recorded_not_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clash = TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Not prompt injection at all")
    _with_taxonomy_provider(monkeypatch, lambda: [clash])
    registry = Registry.discover(PluginTrust(mode=PluginMode.ALL))
    assert any("LLM01" in error.reason for error in registry.load_errors)
    # The built-in meaning survives: a report's mapping cannot be rewritten by an
    # installed package. Asked by reference and not by bare id, because a bare
    # `LLM01` is now itself refused — had the clash been registered, it would have
    # answered that bare lookup and quietly become what `LLM01` means.
    builtin = resolve("LLM01:2025")
    assert builtin is not None
    assert builtin.title == "Prompt Injection"
    with pytest.raises(TaxonomyError, match="which edition"):
        resolve("LLM01")


def _with_taxonomy_provider(
    monkeypatch: pytest.MonkeyPatch, provide: Callable[[], list[TaxonomyRef]]
) -> None:
    """Make `entry_points(group="guardana.taxonomies")` yield one fake provider."""

    class _Fake(EntryPoint):
        def load(self) -> Callable[[], list[TaxonomyRef]]:
            return provide

    fake = _Fake(name="acme", value="acme:provide", group="guardana.taxonomies")

    def fake_entry_points(*, group: str) -> tuple[EntryPoint, ...]:
        if group == "guardana.taxonomies":
            return (fake,)
        return tuple(entry_points(group=group))

    monkeypatch.setattr("guardana.core.entrypoints.entry_points", fake_entry_points)


def test_a_provider_that_fails_part_way_leaves_none_of_its_references_behind(
    forget_acme: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clash = TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Not prompt injection at all")
    _with_taxonomy_provider(monkeypatch, lambda: [_ACME, clash])

    registry = Registry.discover(PluginTrust(mode=PluginMode.ALL))

    assert any("LLM01" in error.reason for error in registry.load_errors)
    assert resolve("ACME-14") is None


def test_a_run_pins_an_installed_framework_and_sees_a_reworded_entry(forget_acme: None) -> None:
    def pinned() -> dict[str, str]:
        coverage = _coverage((), (), (), {}, ())
        return {record.framework: record.digest for record in coverage.taxonomies}

    register(_ACME)
    before = pinned()
    _taxonomy_registry.forget("ACME-14")
    register(TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change review"))
    after = pinned()

    assert "ACME-CONTROLS-1" in before
    assert before["ACME-CONTROLS-1"] != after["ACME-CONTROLS-1"]
    assert {k: v for k, v in before.items() if k != "ACME-CONTROLS-1"} == {
        k: v for k, v in after.items() if k != "ACME-CONTROLS-1"
    }


def test_a_control_added_to_a_built_in_framework_is_pinned_beside_its_catalogue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    atlas = next(catalog for catalog in catalogs() if catalog.framework == "MITRE-ATLAS")
    added = TaxonomyRef("MITRE-ATLAS", "AML.T9999", "Control a pack adds")
    monkeypatch.setattr(
        "guardana.core.manifest.build.extensions",
        lambda: {"MITRE-ATLAS": (added,)},
    )

    records = [r for r in _coverage((), (), (), {}, ()).taxonomies if r.framework == "MITRE-ATLAS"]

    assert {(r.digest, r.entries) for r in records} == {
        (atlas.digest, len(atlas.refs)),
        (catalogue_digest((added,)), 1),
    }


def test_only_references_beyond_the_built_in_catalogues_are_extensions() -> None:
    added = TaxonomyRef("MITRE-ATLAS", "AML.T9999", "Control a pack adds")
    assert extensions() == {}
    register(added)
    try:
        assert extensions() == {"MITRE-ATLAS": (added,)}
    finally:
        _taxonomy_registry.forget(added.reference)
