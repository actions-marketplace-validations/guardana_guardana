"""A lock pins what a check *is*, not what its package is called.

The distinction is the whole feature. A pack can sharpen a corpus, widen a prompt
set or swap an evaluator inside one patch release; every one of those changes what a
run tests, and a version pin says nothing moved. `Rule.digest()` has existed since
0.6 so that a comparison could tell those apart, and this is that same knowledge
written down before the run rather than after it.

The round-trip gate is here rather than in its own file because a lock is read on
every CI run of every repository that keeps one: a field written and not read back
is a pin that silently stops pinning.
"""

from dataclasses import replace
from typing import cast

import pytest
from _roundtrip import Document, lost_fields, undemonstrative_fields, unread_keys
from guardana.core.pack.lock import (
    LOCK_SCHEMA_VERSION,
    DriftKind,
    Installed,
    Lock,
    LockedPack,
    catalogue_digest,
    compare,
    lock_from_dict,
    lock_of,
    lock_to_dict,
)
from guardana.core.pack.model import ApiRange as Range
from guardana.core.pack.model import PackError, PackManifest
from guardana.core.taxonomy import TaxonomyRef

_ACME = TaxonomyRef(scheme="ACME-CONTROLS", id="ACME-14", title="Internal data stays internal")


def _manifest() -> PackManifest:
    return PackManifest(
        name="acme-guardana-rules",
        extension_api=Range(minimum=1, below=2),
        source="guardana-pack.yaml",
        rules=("acme.agent.customer_data",),
        evaluators=("acme.strict_refusal",),
        targets=("AcmePromptLibraryTarget",),
        taxonomies=("ACME-CONTROLS",),
        renderers=("acme-table",),
        reporters=("acme-webhook",),
        output_api=Range(minimum=1, below=2),
    )


_UNPINNABLE = "legacy.inherited_rule"
"""A rule registered by a package that declares no manifest.

Part of the base fixture rather than a special case, because a repository with one
is the ordinary situation this file has to keep honest: every assertion below runs
against a build that has something the lock cannot attribute to a pack.
"""


def _installed() -> Installed:
    return Installed(
        rules={"acme.agent.customer_data": "1111222233334444", _UNPINNABLE: "cafebabe00000000"},
        evaluators={"acme.strict_refusal": "acme-guardana-rules"},
        targets={"AcmePromptLibraryTarget": "acme-guardana-rules"},
        catalogues={"ACME-CONTROLS": catalogue_digest([_ACME])},
        renderers={"acme-table": "acme-guardana-rules"},
        reporters={"acme-webhook": "acme-guardana-rules"},
    )


def _lock() -> Lock:
    return lock_of([("acme-guardana-rules", "0.3.1", _manifest())], _installed())


# --- what the lock pins, and how strongly --------------------------------------


def test_a_rule_whose_declaration_changed_is_drift_even_at_the_same_version() -> None:
    """The reason this is not a version lock, stated as behaviour.

    A pack that sharpens a corpus in a patch release ships a different test under
    the same version. A lock that could not see that would let the next comparison
    blame the model for what the rule change did.
    """
    sharpened = replace(
        _installed(),
        rules={"acme.agent.customer_data": "aaaabbbbccccdddd", _UNPINNABLE: "cafebabe00000000"},
    )

    drift = compare(_lock(), lock_of([("acme-guardana-rules", "0.3.1", _manifest())], sharpened))

    assert [entry.kind for entry in drift] == [DriftKind.CHANGED]
    assert "acme.agent.customer_data" in drift[0].subject


def test_a_catalogue_that_retitled_a_control_is_drift() -> None:
    """A re-titled control changes what every finding mapping to it says in an audit.

    It moves no rule, so nothing else in this repository would notice — which is
    exactly why the digest covers the display data and not only the identity.
    """
    retitled = replace(
        _installed(),
        catalogues={
            "ACME-CONTROLS": catalogue_digest([replace(_ACME, title="Data handling, revised")])
        },
    )

    drift = compare(_lock(), lock_of([("acme-guardana-rules", "0.3.1", _manifest())], retitled))

    assert [entry.kind for entry in drift] == [DriftKind.CHANGED]
    assert drift[0].subject == "ACME-CONTROLS"


def test_a_version_change_is_reported_even_when_every_digest_matches() -> None:
    """The coarse pin, and it still earns its place.

    A rule's digest covers its declaration and cannot cover the Python behind it,
    so a package version that moved while every digest held is the one signal left
    that the implementation may have.
    """
    drift = compare(_lock(), lock_of([("acme-guardana-rules", "0.4.0", _manifest())], _installed()))

    assert [entry.kind for entry in drift] == [DriftKind.VERSION_CHANGED]


def test_a_pack_that_disappeared_is_drift_and_says_what_it_cost() -> None:
    """Coverage a team still believes they have is the direction that matters most."""
    drift = compare(_lock(), Lock())

    # The unpinnable rule goes with it: an uninstalled build has neither, and both
    # facts are reported rather than folded into one line about the pack.
    assert [entry.kind for entry in drift] == [DriftKind.PACK_MISSING, DriftKind.REMOVED]
    assert "not installed" in drift[0].detail


def test_a_pack_nobody_pinned_is_drift() -> None:
    """The supply-chain direction: a rule pack running in CI that no lock mentions."""
    drift = compare(Lock(), _lock())

    assert [entry.kind for entry in drift] == [DriftKind.PACK_UNLOCKED, DriftKind.ADDED]


def test_a_rule_added_since_the_lock_is_reported_as_well_as_one_removed() -> None:
    """Both directions, because a check nobody reviewed is not an improvement."""
    grown = replace(
        _installed(),
        rules={
            "acme.agent.customer_data": "1111222233334444",
            "acme.prompt.overreach": "5555666677778888",
            _UNPINNABLE: "cafebabe00000000",
        },
    )
    manifest = replace(_manifest(), rules=("acme.agent.customer_data", "acme.prompt.overreach"))

    drift = compare(_lock(), lock_of([("acme-guardana-rules", "0.3.1", manifest)], grown))

    assert [entry.kind for entry in drift] == [DriftKind.ADDED]
    assert drift[0].subject == "acme.prompt.overreach"


def test_an_extension_no_manifest_declares_is_recorded_as_unpinnable() -> None:
    """A lock that omitted it would report a fully pinned repository that is not one."""
    assert _lock().unlocked == (_UNPINNABLE,)


def test_an_unpinnable_extension_appearing_later_is_drift() -> None:
    """Recording it is not enough: it has to be *compared*, or the record is decoration."""
    stray = replace(
        _installed(),
        rules={
            "acme.agent.customer_data": "1111222233334444",
            _UNPINNABLE: "cafebabe00000000",
            "rogue.rule": "9999",
        },
    )

    drift = compare(_lock(), lock_of([("acme-guardana-rules", "0.3.1", _manifest())], stray))

    assert [entry.kind for entry in drift] == [DriftKind.ADDED]
    assert drift[0].subject == "rogue.rule"


# --- the document itself -------------------------------------------------------


def test_every_field_of_a_lock_survives_being_written_and_read_back() -> None:
    restored = lock_from_dict(lock_to_dict(_lock()), "guardana-lock.yaml")

    lost = lost_fields(_lock(), restored, "lock")
    assert not lost, "fields a lock records and a reader never gets back:\n  " + "\n  ".join(lost)


def test_no_key_of_a_lock_can_be_deleted_without_the_reader_noticing() -> None:
    document: Document = lock_to_dict(_lock())

    ignored = unread_keys(
        document,
        lambda doc: lock_from_dict(doc, "guardana-lock.yaml"),
        root="lock",
        refusal=PackError,
    )

    assert not ignored, (
        "keys a lock carries that make no difference to what is read back — a pin "
        "nothing reads is a pin that stopped pinning:\n  " + "\n  ".join(ignored)
    )


def test_the_fixture_occupies_every_field_a_lock_has() -> None:
    """`migrated_from` describes the file that was read and is never written, so it is exempt."""
    empty = undemonstrative_fields(_lock(), "lock", exempt=frozenset({"lock.migrated_from"}))

    assert not empty, f"fields the lock fixture leaves empty, so nothing is proved: {empty}"


@pytest.mark.parametrize(
    "document",
    [
        {"packs": []},
        {"schema_version": LOCK_SCHEMA_VERSION + 1, "packs": []},
        {"schema_version": LOCK_SCHEMA_VERSION, "extension_api": 1, "packs": {}},
        {"schema_version": LOCK_SCHEMA_VERSION, "extension_api": 1, "packs": [{"name": "x"}]},
    ],
)
def test_a_lock_this_build_cannot_read_exactly_is_refused(document: dict[str, object]) -> None:
    """Read in part is worse than not read: a gate that passes on the half it understood."""
    with pytest.raises(PackError):
        lock_from_dict(document, "guardana-lock.yaml")


def test_the_lock_fixture_pins_something_from_every_group() -> None:
    """What makes the round trip above mean anything, at the level below the dataclass.

    `LockedPack` can be fully populated while every collection inside it is empty,
    and an empty collection round-trips whether or not anything reads it.
    """
    (pack,) = _lock().packs

    assert undemonstrative_fields(pack, "pack") == []


def test_a_locked_pack_carries_only_what_the_manifest_declared() -> None:
    """The attribution rule: a lock says which pack a check came from, or does not claim it.

    An id the pack registers but its manifest does not declare is `pack validate`'s
    business, not the lock's — and quietly attributing it here would make the lock
    disagree with the validator about what the pack provides.
    """
    undeclared = replace(_manifest(), rules=())

    locked = lock_of([("acme-guardana-rules", "0.3.1", undeclared)], _installed())

    assert locked.packs[0].rules == {}
    assert "acme.agent.customer_data" in locked.unlocked


def test_a_lock_of_a_taxonomy_only_pack_pins_the_catalogue() -> None:
    """The pack shape schema 2 made expressible has to be lockable too, or it is half a feature."""
    catalogue_only = PackManifest(
        name="acme-controls",
        extension_api=Range(minimum=1, below=2),
        source="guardana-pack.yaml",
        taxonomies=("ACME-CONTROLS",),
    )

    locked = lock_of(
        [("acme-controls", "1.0.0", catalogue_only)],
        Installed(catalogues={"ACME-CONTROLS": catalogue_digest([_ACME])}),
    )

    assert locked.packs[0].taxonomies == {"ACME-CONTROLS": catalogue_digest([_ACME])}
    assert locked.unlocked == ()


def test_an_identical_build_produces_no_drift() -> None:
    """The false-red side. A lock that flagged an unchanged build is a lock nobody keeps."""
    assert compare(_lock(), _lock()) == ()


def test_the_lock_is_written_in_a_stable_order() -> None:
    """A lock that reorders itself makes every diff unreadable and every review a re-read."""
    shuffled = Lock(
        packs=(
            LockedPack(name="zeta", distribution="zeta", version="1.0"),
            LockedPack(name="alpha", distribution="alpha", version="1.0"),
        )
    )

    written = lock_to_dict(shuffled)

    packs = cast("list[dict[str, str]]", written["packs"])
    assert [pack["name"] for pack in packs] == ["alpha", "zeta"]


# --- what a lock refuses to pin, and what it must not overlook ---------------------


def test_the_same_pack_shipped_by_another_distribution_is_drift() -> None:
    """Same name, version and ids, other code: the evaluators behind those ids are not pinned."""
    fork = "acme-rules-fork"
    installed = replace(
        _installed(),
        evaluators={"acme.strict_refusal": fork},
        targets={"AcmePromptLibraryTarget": fork},
        renderers={"acme-table": fork},
        reporters={"acme-webhook": fork},
    )
    replaced = lock_of([(fork, "0.3.1", _manifest())], installed)

    drift = compare(_lock(), replaced)

    assert drift, "a pack now shipped by another distribution compared as matching"
    assert [entry.kind for entry in drift] == ["distribution_changed"]
    assert "acme-rules-fork" in drift[0].detail


_PROMISING = {
    "rule": replace(_manifest(), rules=(*_manifest().rules, "acme.promised")),
    "evaluator": replace(_manifest(), evaluators=(*_manifest().evaluators, "acme.promised")),
    "target": replace(_manifest(), targets=(*_manifest().targets, "acme.promised")),
    "catalogue": replace(_manifest(), taxonomies=(*_manifest().taxonomies, "acme.promised")),
}


@pytest.mark.parametrize("group", sorted(_PROMISING))
def test_a_lock_is_refused_when_a_pack_declares_what_nothing_registers(group: str) -> None:
    """A partial lock is a pin a later `--check` matches while the declared check never runs."""
    manifest = _PROMISING[group]

    with pytest.raises(PackError, match=rf"acme-guardana-rules declares {group} acme\.promised"):
        lock_of([("acme-guardana-rules", "0.3.1", manifest)], _installed())


_IMPOSTER = "acme-imposter"

_REGISTERED_ELSEWHERE = {
    "evaluator": replace(_installed(), evaluators={"acme.strict_refusal": _IMPOSTER}),
    "target": replace(_installed(), targets={"AcmePromptLibraryTarget": _IMPOSTER}),
    "renderer": replace(_installed(), renderers={"acme-table": _IMPOSTER}),
    "reporter": replace(_installed(), reporters={"acme-webhook": _IMPOSTER}),
}

_DECLARED = {
    "evaluator": "acme.strict_refusal",
    "target": "AcmePromptLibraryTarget",
    "renderer": "acme-table",
    "reporter": "acme-webhook",
}


@pytest.mark.parametrize("kind", sorted(_REGISTERED_ELSEWHERE))
def test_a_lock_is_not_written_over_an_extension_another_distribution_registers(
    kind: str,
) -> None:
    """The id is the pack's; the code behind it is not, so pinning it would pin the wrong code."""
    with pytest.raises(PackError) as refused:
        lock_of(
            [("acme-guardana-rules", "0.3.1", _manifest())],
            _REGISTERED_ELSEWHERE[kind],
            writing=True,
        )

    named = f"acme-guardana-rules declares {kind} {_DECLARED[kind]}, which {_IMPOSTER} registers"
    assert str(refused.value) == (
        "a pack declares an extension another distribution registers, so a lock would "
        f"pin code the pack does not ship: {named}"
    )


@pytest.mark.parametrize("kind", sorted(_REGISTERED_ELSEWHERE))
def test_a_check_reports_an_extension_another_distribution_now_registers_as_removed(
    kind: str,
) -> None:
    """Dropped from the pack rather than kept, so the lock on disk no longer matches it."""
    present = lock_of([("acme-guardana-rules", "0.3.1", _manifest())], _REGISTERED_ELSEWHERE[kind])

    drift = compare(_lock(), present)

    removed = [entry for entry in drift if entry.kind == DriftKind.REMOVED]
    assert [entry.subject for entry in removed] == [_DECLARED[kind]]
    assert removed[0].detail == f"{kind} was locked and is gone"


def test_an_evaluator_no_distribution_can_be_named_for_is_not_the_packs_either() -> None:
    """Registered in code, it cannot be shown to be what the pack ships."""
    unnamed = replace(_installed(), evaluators={"acme.strict_refusal": None})

    with pytest.raises(PackError, match=r"acme\.strict_refusal, which an unnamed distribution"):
        lock_of([("acme-guardana-rules", "0.3.1", _manifest())], unnamed, writing=True)


def test_the_packs_own_evaluators_and_targets_are_still_pinned() -> None:
    """The inversion: a pack registering what it declares writes and checks clean."""
    written = lock_of([("acme-guardana-rules", "0.3.1", _manifest())], _installed(), writing=True)

    (pack,) = written.packs
    assert pack.evaluators == ("acme.strict_refusal",)
    assert pack.targets == ("AcmePromptLibraryTarget",)
    assert compare(_lock(), written) == ()


def test_two_installed_packs_of_one_name_are_refused_rather_than_one_dropped() -> None:
    """Keyed by name, the second pack and its rules would never be compared at all."""
    fork = replace(_manifest(), rules=())

    with pytest.raises(PackError, match="acme-guardana-rules from acme-fork, acme-guardana-rules"):
        lock_of(
            [("acme-guardana-rules", "0.3.1", _manifest()), ("acme-fork", "9.9.9", fork)],
            _installed(),
        )


def test_a_lock_file_naming_one_pack_twice_is_refused() -> None:
    written = lock_to_dict(_lock())
    packs = cast("list[dict[str, object]]", written["packs"])
    written["packs"] = [*packs, {**packs[0], "distribution": "acme-fork"}]

    with pytest.raises(PackError, match="more than once"):
        lock_from_dict(written, "guardana-lock.yaml")


def test_a_comparison_of_a_hand_built_lock_naming_one_pack_twice_is_refused() -> None:
    twice = replace(_lock(), packs=(*_lock().packs, replace(_lock().packs[0], distribution="fork")))

    with pytest.raises(PackError, match="more than once"):
        compare(_lock(), twice)


def test_one_pack_name_from_one_distribution_still_locks() -> None:
    assert [pack.name for pack in _lock().packs] == ["acme-guardana-rules"]
