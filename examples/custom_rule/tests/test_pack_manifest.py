"""This pack's manifest says what it provides, and `pack validate` checks it.

Run in the isolated environment CI builds for this example, which is the only place
a third party's entry points and a third party's manifest are both real. The main
suite cannot see this: installing `acme.*` into it would skew the dogfood scan.
"""

from importlib import resources

import acme_rules
from acme_rules.prompt_library_target import AcmePromptLibraryTarget
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    PackManifest,
    Registered,
    check_pack,
    installed_manifests,
    load_manifest,
)
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.target import TargetKind

_ACME = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-guardana-rules"}))


def _manifest() -> PackManifest:
    with resources.as_file(resources.files("acme_rules").joinpath("guardana-pack.yaml")) as path:
        return load_manifest(path)


def test_the_manifest_ships_inside_the_wheel() -> None:
    """`pack validate` runs against an installed distribution, not a source tree.

    A manifest left out of the wheel is one a user cannot read from what they
    installed — which is the only moment compatibility can actually be checked.
    """
    assert resources.files("acme_rules").joinpath("guardana-pack.yaml").is_file()


def test_this_build_can_load_this_pack() -> None:
    assert _manifest().loadable_by()
    assert _manifest().loadable_by(EXTENSION_API_VERSION)


def test_the_manifest_lists_exactly_what_the_entry_points_register() -> None:
    """The failure that matters is the missing one, so it is asserted both ways."""
    registered = _registered_ids() | {target.__name__ for target in acme_rules.provide_targets()}

    assert set(_manifest().provides) == registered


def test_validate_finds_this_pack_through_its_entry_point() -> None:
    """Discovery has to work for an installed third-party package, not just for ours."""
    found = [m for m in installed_manifests(_ACME) if m.name == "acme-guardana-rules"]

    assert found, "the pack registers entry points and ships a manifest, so it must be found"


def test_a_promise_the_package_does_not_keep_is_reported() -> None:
    """Inverted by removing a registration rather than by editing the manifest.

    The check exists for the case where the two drift apart; testing it by deleting
    a line from the manifest would only prove the parser reads fewer lines.
    """
    rules = {r.meta.id: None for r in acme_rules.provide_rules()}
    del rules["acme.agent.customer_data"]

    check = check_pack(_manifest(), Registered(rules=rules))

    assert not check.ok
    assert "acme.agent.customer_data" in check.problems[0]
    assert "believes a check runs that does not" in check.problems[0]


def test_the_target_entry_point_is_registered_and_declared() -> None:
    """`guardana.targets` is in the contract table and had no example until 0.18.1.

    Nothing registering one meant `Registry.targets()` came back empty in every
    install, so `pack validate` could omit targets from its "what is registered" set
    and accuse any pack shipping one — with no example able to notice. This closes
    both halves: the entry point is exercised, and the manifest declares it.
    """
    registered = {target.__name__ for target in Registry.discover(_ACME).targets()}

    assert "AcmePromptLibraryTarget" in registered
    assert "AcmePromptLibraryTarget" in _manifest().provides
    assert check_pack(_manifest(), _registered(targets=registered)).ok
    assert AcmePromptLibraryTarget("/no/such/dir").kind is TargetKind.ARTIFACT


def test_a_prompt_library_that_is_not_there_lists_nothing_rather_than_raising() -> None:
    """A repository with no prompt library has none to check.

    What a rule over this target must not do is read that as "the templates are
    fine" — which is why the docstring points at declining, and why this asserts the
    empty list rather than an exception a rule would have to guess about.
    """
    assert AcmePromptLibraryTarget("/no/such/dir").templates() == []


def _registered(*, targets: set[str]) -> Registered:
    """Every id this pack's entry points register, each under its own kind."""
    return Registered(
        rules={rule.meta.id: None for rule in acme_rules.provide_rules()},
        evaluators={evaluator.id: None for evaluator in acme_rules.provide_evaluators()},
        targets=dict.fromkeys(targets),
        taxonomies={ref.framework: None for ref in acme_rules.provide_taxonomies()},
    )


def _registered_ids() -> set[str]:
    """Every id this pack's entry points register, in the vocabulary the manifest uses.

    All four groups. Taxonomies are compared by **framework**, which is the unit a
    pack registers and the unit `provides.taxonomies` declares — and leaving them out
    is not a detail: this set is what `check_pack` is asked to believe, so a group
    missing from it accuses the manifest of promising something it does register.
    That is the false red `guardana.targets` produced for a whole release, and the
    fourth group had exactly the same hole waiting in it.
    """
    return (
        {rule.meta.id for rule in acme_rules.provide_rules()}
        | {evaluator.id for evaluator in acme_rules.provide_evaluators()}
        | {ref.framework for ref in acme_rules.provide_taxonomies()}
    )
