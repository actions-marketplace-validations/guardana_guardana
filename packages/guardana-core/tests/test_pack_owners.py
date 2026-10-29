"""A pack's claim to an evaluator, a target or a framework is checked against who registered it.

An id another distribution supplies disappears with that distribution while the
manifest still promises it, so every kind a manifest declares is compared with the
distribution that registered it, not only with whether something did.
"""

from collections.abc import Callable, Iterator
from importlib.metadata import EntryPoint

import pytest
from guardana.core.entrypoints import (
    EVALUATOR_GROUP,
    TARGET_GROUP,
    TAXONOMY_GROUP,
    InstalledEntryPoint,
)
from guardana.core.evaluator import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.origin import UNATTRIBUTED, Origin
from guardana.core.pack import ApiRange, PackManifest, check_pack
from guardana.core.pack.discover import Registered
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.taxonomy import TaxonomyRef, catalogs, resolve
from guardana.core.taxonomy._builtin import index as _taxonomy_registry

_ALL = PluginTrust(mode=PluginMode.ALL)
_CATALOGUES = "guardana-core"
"""The distribution this workspace installs the built-in catalogues from."""
_ACME = TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")
_ATLAS_ADDITION = TaxonomyRef("MITRE-ATLAS", "AML.T9999", "Control a pack adds")


class _Judge(Evaluator):
    id = "acme.judge"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        return Verdict("pass", 1.0, "ok", self.id)


class _AcmeTarget(Target):
    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        return "acme"


@pytest.fixture
def forget_references() -> Iterator[None]:
    yield
    for ref in (_ACME, _ATLAS_ADDITION):
        _taxonomy_registry.forget(ref.reference)


def _installed(group: str, distribution: str, provide: Callable[[], object]) -> InstalledEntryPoint:
    """An entry point `distribution` advertises in `group`, whose provider is `provide`."""

    class _Loaded(EntryPoint):
        def load(self) -> Callable[[], object]:
            return provide

    module = distribution.replace("-", "_")
    entry_point = _Loaded(name=distribution, value=f"{module}:provide", group=group)
    return InstalledEntryPoint(
        group=group,
        name=distribution,
        value=entry_point.value,
        module=module,
        distribution=distribution,
        version="1.0",
        entry_point=entry_point,
    )


def _discover(monkeypatch: pytest.MonkeyPatch, *installed: InstalledEntryPoint) -> Registry:
    monkeypatch.setattr("guardana.core.registry.installed_entry_points", lambda: installed)
    return Registry.discover(_ALL)


def test_the_registry_names_the_distribution_behind_an_evaluator_and_a_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _discover(
        monkeypatch,
        _installed(EVALUATOR_GROUP, "acme-judges", lambda: [_Judge()]),
        _installed(TARGET_GROUP, "acme-targets", lambda: [_AcmeTarget]),
    )

    assert registry.evaluator_origin("acme.judge").distribution == "acme-judges"
    assert registry.target_origin(_AcmeTarget).distribution == "acme-targets"
    assert registry.evaluator_origin("nobody.registered.this") == UNATTRIBUTED


def test_a_target_name_two_distributions_register_is_a_load_error_naming_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second registrant is refused whole, so the first keeps the origin it was given."""

    class _Imposter(_AcmeTarget):
        pass

    _Imposter.__name__ = _AcmeTarget.__name__

    registry = _discover(
        monkeypatch,
        _installed(TARGET_GROUP, "acme-targets", lambda: [_AcmeTarget]),
        _installed(TARGET_GROUP, "acme-imposter", lambda: [_Imposter]),
    )

    (error,) = registry.load_errors
    assert error.source == "acme-imposter"
    assert "acme-targets 1.0" in error.reason
    assert "acme-imposter 1.0" in error.reason
    assert registry.targets() == (_AcmeTarget,)
    assert registry.target_origin(_AcmeTarget).distribution == "acme-targets"


def test_a_target_keeps_the_origin_it_was_registered_with() -> None:
    registry = Registry()
    registry.register_target(_AcmeTarget, Origin(distribution="acme-targets"))

    assert registry.target_origin(_AcmeTarget).distribution == "acme-targets"
    assert Registry().target_origin(_AcmeTarget) == UNATTRIBUTED


def test_two_distributions_registering_an_identical_reference_are_both_owners(
    monkeypatch: pytest.MonkeyPatch, forget_references: None
) -> None:
    registry = _discover(
        monkeypatch,
        _installed(TAXONOMY_GROUP, "acme-one", lambda: [_ACME]),
        _installed(TAXONOMY_GROUP, "acme-two", lambda: [_ACME]),
    )

    owners = registry.taxonomy_owners()
    assert owners["ACME-CONTROLS-1"] == frozenset({"acme-one", "acme-two"})


def test_a_control_added_to_a_built_in_framework_makes_its_distribution_an_owner(
    monkeypatch: pytest.MonkeyPatch, forget_references: None
) -> None:
    registry = _discover(
        monkeypatch, _installed(TAXONOMY_GROUP, "acme-one", lambda: [_ATLAS_ADDITION])
    )

    assert registry.taxonomy_owners()["MITRE-ATLAS"] == frozenset({_CATALOGUES, "acme-one"})


def test_a_built_in_framework_is_owned_by_the_distribution_shipping_the_catalogues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _discover(monkeypatch)

    owners = registry.taxonomy_owners()
    assert {catalog.framework for catalog in catalogs()} <= set(owners)
    assert owners["MITRE-ATLAS"] == frozenset({_CATALOGUES})


def test_a_provider_that_fails_part_way_leaves_no_owner_behind(
    monkeypatch: pytest.MonkeyPatch, forget_references: None
) -> None:
    clash = TaxonomyRef("ACME-CONTROLS-1", "LLM01", "Not prompt injection at all")
    registry = _discover(
        monkeypatch,
        _installed(TAXONOMY_GROUP, "acme-one", lambda: [_ACME]),
        _installed(TAXONOMY_GROUP, "acme-two", lambda: [_ACME, clash]),
    )

    assert any("LLM01" in error.reason for error in registry.load_errors)
    assert registry.taxonomy_owners()["ACME-CONTROLS-1"] == frozenset({"acme-one"})
    assert resolve("ACME-14") == _ACME


def test_a_copied_registry_keeps_its_owners_apart(
    monkeypatch: pytest.MonkeyPatch, forget_references: None
) -> None:
    registry = _discover(monkeypatch, _installed(TAXONOMY_GROUP, "acme-one", lambda: [_ACME]))

    copy = registry.copied()
    copy._record_taxonomy(_ATLAS_ADDITION, Origin(distribution="acme-two"))

    assert registry.taxonomy_owners()["MITRE-ATLAS"] == frozenset({_CATALOGUES})
    assert copy.taxonomy_owners()["MITRE-ATLAS"] == frozenset({_CATALOGUES, "acme-two"})
    assert copy.taxonomy_owners()["ACME-CONTROLS-1"] == frozenset({"acme-one"})


def _manifest(
    *,
    evaluators: tuple[str, ...] = (),
    targets: tuple[str, ...] = (),
    taxonomies: tuple[str, ...] = (),
) -> PackManifest:
    return PackManifest(
        "acme",
        ApiRange(1, 3),
        "x",
        evaluators=evaluators,
        targets=targets,
        taxonomies=taxonomies,
    )


def test_an_evaluator_another_distribution_registers_is_not_this_packs_promise_kept() -> None:
    check = check_pack(
        _manifest(evaluators=("canary",)),
        Registered(evaluators={"canary": "guardana-rules"}),
        "acme-rules",
    )

    assert not check.ok
    assert "evaluator canary (registered by guardana-rules)" in check.problems[0]


def test_an_evaluator_the_shipping_distribution_registers_is_a_kept_promise() -> None:
    registered = Registered(evaluators={"acme.judge": "acme-rules"})

    assert check_pack(_manifest(evaluators=("acme.judge",)), registered, "acme-rules").ok


def test_a_target_another_distribution_registers_is_not_this_packs_promise_kept() -> None:
    check = check_pack(
        _manifest(targets=("AcmeTarget",)),
        Registered(targets={"AcmeTarget": "other-targets"}),
        "acme-rules",
    )

    assert not check.ok
    assert "target AcmeTarget (registered by other-targets)" in check.problems[0]


def test_a_target_the_shipping_distribution_registers_is_a_kept_promise() -> None:
    registered = Registered(targets={"AcmeTarget": "acme-rules"})

    assert check_pack(_manifest(targets=("AcmeTarget",)), registered, "acme-rules").ok


def test_a_framework_only_another_distribution_registers_into_is_not_this_packs() -> None:
    registered = Registered(
        taxonomies={"ACME-CONTROLS-1": None},
        taxonomy_owners={"ACME-CONTROLS-1": frozenset({"other-controls", "more-controls"})},
    )

    check = check_pack(_manifest(taxonomies=("ACME-CONTROLS-1",)), registered, "acme-rules")

    assert not check.ok
    assert (
        "taxonomy ACME-CONTROLS-1 (registered by more-controls, other-controls)"
        in check.problems[0]
    )


def test_a_framework_the_shipping_distribution_registers_into_is_a_kept_promise() -> None:
    registered = Registered(
        taxonomies={"ACME-CONTROLS-1": None},
        taxonomy_owners={"ACME-CONTROLS-1": frozenset({"other-controls", "acme-rules"})},
    )

    assert check_pack(_manifest(taxonomies=("ACME-CONTROLS-1",)), registered, "acme-rules").ok


def test_a_pack_adding_controls_to_a_built_in_framework_keeps_its_promise() -> None:
    registered = Registered(
        taxonomies={"MITRE-ATLAS": None},
        taxonomy_owners={"MITRE-ATLAS": frozenset({"acme-rules"})},
    )

    assert check_pack(_manifest(taxonomies=("MITRE-ATLAS",)), registered, "acme-rules").ok


def test_a_manifest_without_a_distribution_is_checked_by_kind_only() -> None:
    registered = Registered(
        evaluators={"canary": "guardana-rules"},
        targets={"AcmeTarget": "other-targets"},
        taxonomies={"ACME-CONTROLS-1": None},
        taxonomy_owners={"ACME-CONTROLS-1": frozenset({"other-controls"})},
    )
    manifest = _manifest(
        evaluators=("canary",), targets=("AcmeTarget",), taxonomies=("ACME-CONTROLS-1",)
    )

    assert check_pack(manifest, registered).ok


@pytest.mark.parametrize(
    ("kind", "registered", "manifest"),
    [
        (
            "rule",
            Registered(rules={"acme.rule": None}),
            PackManifest("acme", ApiRange(1, 3), "x", rules=("acme.rule",)),
        ),
        ("evaluator", Registered(evaluators={"canary": None}), _manifest(evaluators=("canary",))),
        ("target", Registered(targets={"AcmeTarget": None}), _manifest(targets=("AcmeTarget",))),
        (
            "taxonomy",
            Registered(taxonomies={"ACME-CONTROLS-1": None}),
            _manifest(taxonomies=("ACME-CONTROLS-1",)),
        ),
    ],
    ids=["rule", "evaluator", "target", "taxonomy"],
)
def test_an_id_no_nameable_distribution_registers_is_not_this_packs_promise_kept(
    kind: str, registered: Registered, manifest: PackManifest
) -> None:
    check = check_pack(manifest, registered, "acme-rules")

    assert not check.ok
    assert any(
        problem.startswith(f"declares {kind} ")
        and "registered by no distribution this build can name" in problem
        for problem in check.problems
    ), check.problems


def test_a_manifest_without_a_distribution_is_not_held_to_an_owner_nobody_can_name() -> None:
    registered = Registered(evaluators={"canary": None}, taxonomies={"ACME-CONTROLS-1": None})
    manifest = _manifest(evaluators=("canary",), taxonomies=("ACME-CONTROLS-1",))

    assert check_pack(manifest, registered).ok
