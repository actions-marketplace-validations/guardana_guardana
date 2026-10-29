"""`guardana pack validate` — and what it must not do when trust is restricted.

The command's whole job is comparing what a manifest promises against what this
build actually registers. Refuse an entry point silently and the "actually
registers" side goes empty while the manifest still promises everything — the
exact false red 0.18.0 shipped when `pack validate` built that set from rules and
evaluators alone and accused every pack that shipped a target of not registering
it. Repeating that shape through `--plugins` instead of a missing group is the
same defect behind a different door.

Printing the refusal on stderr (`warn_about_load_errors`) made it visible; it did
not make the verdict correct. `validate` still built `registered` from the same
emptied registry and printed "declares … and does not register" as a fact about
the pack — the exact accusation the module docstring says a validator must never
make, just reached through a policy instead of a missing entry-point group. The
fix refuses the comparison outright rather than reporting it wrong.
"""

from collections.abc import Callable, Iterator
from dataclasses import replace
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest
from guardana.cli import pack
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import (
    TARGET_GROUP,
    TAXONOMY_GROUP,
    InstalledEntryPoint,
    installed_entry_points,
)
from guardana.core.pack import ApiRange, PackDiscovery, PackManifest, discover_packs
from guardana.core.plugins import PluginTrust
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.taxonomy._builtin import index as _taxonomy_registry
from typer.testing import CliRunner

runner = CliRunner()


def _one_package_without_a_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make discovery report `acme_rules` as registering extensions with no manifest."""

    def discovered(trust: PluginTrust) -> PackDiscovery:
        return replace(discover_packs(trust), unmanifested=("acme_rules",))

    monkeypatch.setattr(pack, "discover_packs", discovered)


def test_a_restrictive_plugin_mode_refuses_rather_than_accuses() -> None:
    """`--plugins disabled` empties "what this build registers". A pack that
    genuinely does not register what it declares and a pack merely refused by
    trust are indistinguishable from inside an emptied registry, so `validate`
    must not accuse either — it must say the comparison could not be made, and
    go indeterminate rather than hand back a confident, wrong answer.
    """
    result = runner.invoke(app, ["pack", "validate", "--plugins", "disabled"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "does not register" not in result.output
    assert "pack(s) checked" not in result.output
    assert "could not load an extension" in result.stderr
    assert "plugin trust is disabled" in result.stderr
    assert "refused by plugin trust" in result.stderr


def test_full_trust_still_catches_a_pack_that_really_does_not_register() -> None:
    """The inversion target: refusing to accuse must not become refusing to check.

    With nothing refused, a mismatch is still exactly the thing this command
    exists to catch — proven here by the ordinary, unrestricted run finding
    every installed pack accurate and saying so by name.
    """
    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "does not register" not in result.output
    assert "pack(s) checked" in result.output


def test_a_package_that_registers_extensions_and_declares_no_manifest_is_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The silence this command used to keep about packs it never read.

    Discovery drops a distribution that ships no manifest, and the
    command went indeterminate only when the list came back empty — which it never
    does, because the built-in pack always has one. A third party whose manifest
    missed the wheel therefore saw "0 with problems" about rules that were live in
    the registry and had been compared against nothing.
    """
    _one_package_without_a_manifest(monkeypatch)

    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "acme_rules" in result.stderr
    assert "declare no manifest" in result.stderr


def test_a_named_manifest_is_answered_without_the_whole_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Asking about one manifest is not asking for a survey of every install.

    The unmanifested note belongs to the discovery run. Attaching it to an explicit
    path would make a question about one file answerable only by the state of the
    environment around it.
    """
    _one_package_without_a_manifest(monkeypatch)
    manifest = tmp_path / "guardana-pack.yaml"
    manifest.write_text(
        "schema_version: 2\nname: borrowed-pack\n"
        'extension_api: ">=1,<3"\n'
        "description: a manifest that claims a rule this build really registers\n"
        "provides:\n  rules:\n    - guardana.prompt.injection.ignore_previous\n"
    )

    result = runner.invoke(app, ["pack", "validate", str(manifest)])

    assert result.exit_code == ExitCode.OK, result.output
    assert "acme_rules" not in result.stderr


_BUILT_IN_RULE = "guardana.prompt.injection.ignore_previous"


def _an_installed_pack(
    monkeypatch: pytest.MonkeyPatch, distribution: str, manifest: PackManifest
) -> None:
    """Make discovery report one more installed pack, shipped by `distribution`."""

    def discovered(trust: PluginTrust) -> PackDiscovery:
        found = discover_packs(trust)
        return replace(found, packs=(*found.packs, (distribution, "0.3.1", manifest)))

    monkeypatch.setattr(pack, "discover_packs", discovered)


def test_an_installed_pack_promising_a_rule_another_distribution_registers_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rule runs, but not from this pack: uninstalling the other one removes it silently."""
    manifest = PackManifest("acme-guardana-rules", ApiRange(1, 3), "x", rules=(_BUILT_IN_RULE,))
    _an_installed_pack(monkeypatch, "acme-guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert _BUILT_IN_RULE in result.stdout
    assert "registered by guardana-rules" in result.stdout


def test_a_rule_id_promised_as_an_evaluator_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shipped by the distribution that registers the id, so only the kind is wrong."""
    manifest = PackManifest("kind-mixup", ApiRange(1, 3), "x", evaluators=(_BUILT_IN_RULE,))
    _an_installed_pack(monkeypatch, "guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert f"evaluator {_BUILT_IN_RULE}" in result.stdout


def test_an_installed_pack_promising_an_evaluator_another_distribution_registers_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = PackManifest("acme-guardana-rules", ApiRange(1, 3), "x", evaluators=("canary",))
    _an_installed_pack(monkeypatch, "acme-guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert "evaluator canary (registered by guardana-rules)" in result.stdout


def test_an_installed_pack_promising_an_evaluator_it_registers_is_accurate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = PackManifest("judges", ApiRange(1, 3), "x", evaluators=("canary",))
    _an_installed_pack(monkeypatch, "guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "registered by" not in result.stdout


class _OtherTarget(Target):
    """A target class another distribution registers."""

    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        return "other"


_OTHER_CONTROL = TaxonomyRef("OTHER-CONTROLS-1", "OTHER-7", "A control another pack registers")
_ADDED_CONTROL = TaxonomyRef("MITRE-ATLAS", "AML.T9998", "A control the pack adds")


@pytest.fixture
def forget_controls() -> Iterator[None]:
    yield
    for ref in (_OTHER_CONTROL, _ADDED_CONTROL):
        _taxonomy_registry.forget(ref.reference)


def _also_installed(monkeypatch: pytest.MonkeyPatch, *extra: InstalledEntryPoint) -> None:
    """Make registry discovery see `extra` beside what is really installed."""
    real = installed_entry_points()
    monkeypatch.setattr("guardana.core.registry.installed_entry_points", lambda: (*real, *extra))


def _provider(group: str, distribution: str, provide: Callable[[], object]) -> InstalledEntryPoint:
    class _Loaded(EntryPoint):
        def load(self) -> Callable[[], object]:
            return provide

    module = distribution.replace("-", "_")
    entry_point = _Loaded(name=distribution, value=f"{module}:provide", group=group)
    return InstalledEntryPoint(
        group, distribution, entry_point.value, module, distribution, "1.0", entry_point
    )


def test_a_pack_promising_a_target_and_a_framework_another_distribution_registers_is_reported(
    monkeypatch: pytest.MonkeyPatch, forget_controls: None
) -> None:
    _also_installed(
        monkeypatch,
        _provider(TAXONOMY_GROUP, "other-pack", lambda: [_OTHER_CONTROL]),
        _provider(TARGET_GROUP, "other-pack", lambda: [_OtherTarget]),
    )
    manifest = PackManifest(
        "acme-guardana-rules",
        ApiRange(1, 3),
        "x",
        targets=("_OtherTarget",),
        taxonomies=("OTHER-CONTROLS-1",),
    )
    _an_installed_pack(monkeypatch, "acme-guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate", "--plugins", "all"])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert "target _OtherTarget (registered by other-pack)" in result.stdout
    assert "taxonomy OTHER-CONTROLS-1 (registered by other-pack)" in result.stdout


def test_a_pack_adding_controls_to_a_built_in_framework_may_declare_it(
    monkeypatch: pytest.MonkeyPatch, forget_controls: None
) -> None:
    _also_installed(
        monkeypatch, _provider(TAXONOMY_GROUP, "acme-guardana-rules", lambda: [_ADDED_CONTROL])
    )
    manifest = PackManifest("acme-guardana-rules", ApiRange(1, 3), "x", taxonomies=("MITRE-ATLAS",))
    _an_installed_pack(monkeypatch, "acme-guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate", "--plugins", "all"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "registered by" not in result.stdout


def test_a_manifest_given_by_path_is_checked_by_kind_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, forget_controls: None
) -> None:
    """A file on disk names no distribution, so nothing can be compared against an owner."""
    _also_installed(
        monkeypatch,
        _provider(TAXONOMY_GROUP, "other-pack", lambda: [_OTHER_CONTROL]),
        _provider(TARGET_GROUP, "other-pack", lambda: [_OtherTarget]),
    )
    manifest = tmp_path / "guardana-pack.yaml"
    manifest.write_text(
        "schema_version: 2\nname: borrowed-pack\n"
        'extension_api: ">=1,<3"\n'
        "description: a manifest that claims what other distributions register\n"
        "provides:\n"
        "  evaluators: [canary]\n"
        "  targets: [_OtherTarget]\n"
        "  taxonomies: [OTHER-CONTROLS-1]\n"
    )

    result = runner.invoke(app, ["pack", "validate", str(manifest), "--plugins", "all"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "registered by" not in result.stdout


def test_a_pack_declaring_a_built_in_framework_it_adds_nothing_to_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The framework is real, but the pack's distribution registers no reference into it."""
    manifest = PackManifest("acme-guardana-rules", ApiRange(1, 3), "x", taxonomies=("MITRE-ATLAS",))
    _an_installed_pack(monkeypatch, "acme-guardana-rules", manifest)

    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert "taxonomy MITRE-ATLAS (registered by guardana-core)" in result.stdout
