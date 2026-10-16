"""What was installed, pinned by what each thing *is* rather than by what it is called.

A lock over distribution versions is not a lock for this project, and the reason is
already in the codebase: `Rule.digest()` exists precisely so that "the same rule"
means more than "the same package version". A pack can sharpen a corpus, widen a
prompt set or swap an evaluator inside one patch release, and every one of those
changes what a run tests while the version string it is pinned by says nothing
moved. A comparison against last week's run would then blame the model.

So this pins three different things with three different strengths, and says which
is which rather than presenting one confidence:

- **rules** by digest — their declaration, hashed. A changed corpus is visible;
- **evaluators, targets, renderers and reporters** by id, and only when the pack's
  own distribution registers them. They are Python and have no declaration to hash,
  and inventing a digest from a class name would claim to detect a change it cannot
  see; an id another distribution registers is not the pack's code, so it is refused
  rather than pinned;
- **catalogues** by a digest over the references a pack registers. A third-party
  catalogue has no *file* to pin — a pack registers refs through an entry point —
  but what it registered is content, and content hashes.

The distribution version is recorded beside all of it as the coarse pin that covers
what none of the above can: the Python implementation behind a rule whose
declaration did not move.
"""

import json
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from guardana.core.fingerprint import digest_of
from guardana.core.pack.model import EXTENSION_API_VERSION, PackError, PackManifest, output_id

LOCK_SCHEMA_VERSION = 3
"""The newest version of `guardana-lock.yaml`, moved independently of everything it pins.

A lock is a document a team keeps in their repository and reads on every CI run, so
principle 11 applies to it exactly as it does to a saved run. Schema 2 nests every
digest as `<id>: {digest: <hex>}`: an id may contain `secret`, `key` or `token`, and
schema 1's `<id>: <hex>` line reads to a secret scanner as a credential. Schema 3
adds `renderers` and `reporters` to every pack entry and is written only when a pack
pins an output or an output is unlocked, so a lock without outputs stays schema 2
and readable by builds that predate outputs.
"""

_SCHEMA_WITHOUT_OUTPUTS = 2
"""The schema written when nothing pins an output."""

_READABLE_LOCK_SCHEMAS = frozenset({1, _SCHEMA_WITHOUT_OUTPUTS, LOCK_SCHEMA_VERSION})

_OUTPUT_KINDS = ("renderer", "reporter")

LOCK_NAME = "guardana-lock.yaml"
"""The conventional filename, at the root of the repository being gated."""


class DriftKind(StrEnum):
    """How what is installed differs from what was locked.

    Seven kinds rather than one "mismatch", because they are seven different things
    to do about it. A rule whose digest moved is a review; a pack nobody pinned, or
    one now shipped by another distribution, is a supply-chain question; a rule that
    vanished is coverage a team still believes they have.
    """

    PACK_MISSING = "pack_missing"
    PACK_UNLOCKED = "pack_unlocked"
    DISTRIBUTION_CHANGED = "distribution_changed"
    VERSION_CHANGED = "version_changed"
    REMOVED = "removed"
    ADDED = "added"
    CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class Drift:
    """One difference between the lock and what is installed."""

    kind: DriftKind
    subject: str
    detail: str

    def describe(self) -> str:
        """One line, naming the thing and what happened to it."""
        return f"{self.kind}: {self.subject} — {self.detail}"


@dataclass(frozen=True, slots=True)
class LockedPack:
    """One pack as it was when the lock was written."""

    name: str
    distribution: str
    version: str
    rules: Mapping[str, str] = field(default_factory=dict)
    evaluators: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    taxonomies: Mapping[str, str] = field(default_factory=dict)
    renderers: tuple[str, ...] = ()
    reporters: tuple[str, ...] = ()

    @property
    def pins_outputs(self) -> bool:
        """Whether this pack pins a renderer or a reporter."""
        return bool(self.renderers or self.reporters)


@dataclass(frozen=True, slots=True)
class Lock:
    """Everything a build had installed, pinned."""

    packs: tuple[LockedPack, ...] = ()
    unlocked: tuple[str, ...] = ()
    """Ids registered by no pack that declares a manifest.

    Recorded rather than dropped. An extension nobody can pin is the single thing a
    lock file exists to make visible, and leaving it out of the document would make
    a repository with an unpinnable pack look fully pinned.
    """

    schema_version: int = _SCHEMA_WITHOUT_OUTPUTS
    """The layout this lock was read as, or the one `lock_of` will have it written as."""

    extension_api: int = EXTENSION_API_VERSION
    migrated_from: int | None = None
    """The schema the file declared, when it was older than the one this build writes.

    Never written: it describes the file that was read, so `pack lock --check` can
    tell the user to rewrite it rather than leave the migration invisible.
    """


def catalogue_digest(refs: Iterable[Any]) -> str:
    """Digest the references a pack registers under one framework.

    Covers identity and display data both: a catalogue that silently re-titles a
    control has changed what every finding mapping to it says in somebody's audit,
    which is a change worth seeing even though it moves no rule.
    """
    entries = sorted(
        (ref.scheme, ref.id, ref.title, ref.edition or "", str(ref.rank or "")) for ref in refs
    )
    return digest_of(json.dumps(entries, sort_keys=True, ensure_ascii=False))


@dataclass(frozen=True, slots=True)
class Installed:
    """What this build has registered, in the vocabulary a lock pins.

    Assembled by the caller from a `Registry` rather than read here, so this module
    stays a document format with no opinion about how extensions are discovered —
    which is also what lets a test build one without installing anything.
    """

    rules: Mapping[str, str] = field(default_factory=dict)
    evaluators: Mapping[str, str | None] = field(default_factory=dict)
    """Every registered evaluator, by id, to the distribution registering it."""

    targets: Mapping[str, str | None] = field(default_factory=dict)
    """Every registered target, by class name, to the distribution registering it."""

    catalogues: Mapping[str, str] = field(default_factory=dict)
    renderers: Mapping[str, str | None] = field(default_factory=dict)
    """Every installed format that can be selected, by name, to the distribution registering it."""

    reporters: Mapping[str, str | None] = field(default_factory=dict)
    """Every installed reporter that can be selected, by name, to its registering distribution."""

    def ids(self) -> set[str]:
        """Every id this build registers, in one set; an output as `<kind>:<name>`."""
        return {
            *self.rules,
            *self.evaluators,
            *self.targets,
            *self.catalogues,
            *(output_id("renderer", name) for name in self.renderers),
            *(output_id("reporter", name) for name in self.reporters),
        }


def lock_of(
    packs: Sequence[tuple[str, str, Any]], installed: Installed, *, writing: bool = False
) -> Lock:
    """Pin what is installed, attributing each id to the pack whose manifest declares it.

    `packs` is `(distribution, version, manifest)` per installed pack.

    A pack pins only the declared evaluators, targets and outputs its own distribution
    registers: an id another distribution registers is not the pack's code, so a lock
    checked against this one reports it `removed`. When `writing`, such an id raises
    `PackError` instead, since the lock would otherwise be written without it.

    An id declared by no manifest lands in `unlocked`. That is the case worth
    designing for rather than dropping: a package registering rules without a
    manifest cannot be pinned by name, and a lock that silently omitted it would
    report a fully pinned repository while an unpinned pack ran in it.

    An id a manifest declares and nothing registers raises `PackError`. Pinned
    without it, the lock would match every later build in which that check never
    runs while the manifest still promises it. So do two packs declaring one name:
    a lock is keyed by pack name, and the second would vanish from every check.
    """
    _refuse_shared_names(
        ((manifest.name, distribution) for distribution, _version, manifest in packs),
        "installed packs",
    )
    undelivered = [
        f"{manifest.name} declares {kind} {', '.join(missing)}"
        for _distribution, _version, manifest in packs
        for kind, missing in _undelivered(manifest, installed)
    ]
    if undelivered:
        raise PackError(
            f"nothing registers what a pack declares, so a lock would pin a check that "
            f"does not run: {'; '.join(undelivered)}"
        )
    foreign = {
        (manifest.name, kind, name): registrant
        for distribution, _version, manifest in packs
        for kind, name, registrant in _foreign(distribution, manifest, installed)
    }
    if writing and foreign:
        named = "; ".join(
            f"{pack} declares {kind} {name}, which {registrant or 'an unnamed distribution'} "
            f"registers"
            for (pack, kind, name), registrant in foreign.items()
        )
        raise PackError(
            f"a pack declares an extension another distribution registers, so a lock would "
            f"pin code the pack does not ship: {named}"
        )
    locked = [
        LockedPack(
            name=manifest.name,
            distribution=distribution,
            version=version,
            rules={i: installed.rules[i] for i in manifest.rules},
            evaluators=_own(manifest.name, "evaluator", manifest.evaluators, foreign),
            targets=_own(manifest.name, "target", manifest.targets, foreign),
            taxonomies={i: installed.catalogues[i] for i in manifest.taxonomies},
            renderers=_own(manifest.name, "renderer", manifest.renderers, foreign),
            reporters=_own(manifest.name, "reporter", manifest.reporters, foreign),
        )
        for distribution, version, manifest in packs
    ]
    declared = {name for pack in locked for name in _pinned_ids(pack)}
    unlocked = tuple(sorted(installed.ids() - declared))
    return Lock(
        packs=tuple(locked),
        unlocked=unlocked,
        schema_version=_written_schema(locked, unlocked),
    )


def _refuse_shared_names(packs: Iterable[tuple[str, str]], where: str) -> None:
    """Raise `PackError` when two `(name, distribution)` pairs share a pack name."""
    shipped: dict[str, list[str]] = {}
    for name, distribution in packs:
        shipped.setdefault(name, []).append(distribution)
    shared = {name: found for name, found in shipped.items() if len(found) > 1}
    if shared:
        named = "; ".join(
            f"{name} from {', '.join(sorted(found))}" for name, found in sorted(shared.items())
        )
        raise PackError(
            f"{where} declare one pack name more than once, so a lock keyed by name would "
            f"compare only one of them: {named}"
        )


def _foreign(
    distribution: str, manifest: PackManifest, installed: Installed
) -> list[tuple[str, str, str | None]]:
    """Every declared extension registered by a distribution other than the pack's own.

    Only the kinds a lock pins by id are checked; a rule or a catalogue is pinned by
    a digest of what was registered.
    """
    groups = (
        ("evaluator", manifest.evaluators, installed.evaluators),
        ("target", manifest.targets, installed.targets),
        ("renderer", manifest.renderers, installed.renderers),
        ("reporter", manifest.reporters, installed.reporters),
    )
    return [
        (kind, name, present[name])
        for kind, declared, present in groups
        for name in declared
        if name in present and present[name] != distribution
    ]


def _own(
    pack: str, kind: str, declared: Sequence[str], foreign: Collection[tuple[str, str, str]]
) -> tuple[str, ...]:
    """Return the ids of `kind` that `pack` declares and its own distribution registers."""
    return tuple(name for name in declared if (pack, kind, name) not in foreign)


def _pinned_ids(pack: LockedPack) -> set[str]:
    """Every id `pack` pins, an output as `<kind>:<name>`."""
    return {
        *pack.rules,
        *pack.evaluators,
        *pack.targets,
        *pack.taxonomies,
        *(output_id("renderer", name) for name in pack.renderers),
        *(output_id("reporter", name) for name in pack.reporters),
    }


def _written_schema(packs: Iterable[LockedPack], unlocked: Iterable[str]) -> int:
    """Choose schema 3 when an output is pinned or unlocked, otherwise schema 2."""
    if any(pack.pins_outputs for pack in packs) or any(_is_output_id(i) for i in unlocked):
        return LOCK_SCHEMA_VERSION
    return _SCHEMA_WITHOUT_OUTPUTS


def _is_output_id(identifier: str) -> bool:
    return identifier.startswith(tuple(f"{kind}:" for kind in _OUTPUT_KINDS))


def _undelivered(manifest: PackManifest, installed: Installed) -> list[tuple[str, list[str]]]:
    """Every group of `manifest` with ids nothing in `installed` registers under that kind."""
    groups: tuple[tuple[str, Sequence[str], Collection[str]], ...] = (
        ("rule", manifest.rules, installed.rules),
        ("evaluator", manifest.evaluators, installed.evaluators),
        ("target", manifest.targets, installed.targets),
        ("catalogue", manifest.taxonomies, installed.catalogues),
        ("renderer", manifest.renderers, installed.renderers),
        ("reporter", manifest.reporters, installed.reporters),
    )
    return [
        (kind, missing)
        for kind, declared, present in groups
        if (missing := [i for i in declared if i not in present])
    ]


def lock_to_dict(lock: Lock) -> dict[str, Any]:
    """Render a lock as the document written to disk.

    The schema follows the content, so a lock that pins no output is written as
    schema 2 whatever `lock.schema_version` says, and one that does is never
    written in a layout that cannot hold it.
    """
    schema = _written_schema(lock.packs, lock.unlocked)
    return {
        "schema_version": schema,
        "extension_api": lock.extension_api,
        "packs": [_pack_to_dict(pack, schema) for pack in sorted(lock.packs, key=lambda p: p.name)],
        "unlocked": list(lock.unlocked),
    }


def _pack_to_dict(pack: LockedPack, schema: int) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": pack.name,
        "distribution": pack.distribution,
        "version": pack.version,
        "rules": _nested(pack.rules),
        "evaluators": list(pack.evaluators),
        "targets": list(pack.targets),
    }
    if schema >= LOCK_SCHEMA_VERSION:
        entry["renderers"] = list(pack.renderers)
        entry["reporters"] = list(pack.reporters)
    entry["taxonomies"] = _nested(pack.taxonomies)
    return entry


def lock_from_dict(raw: object, source: str) -> Lock:
    """Read a lock, refusing anything it cannot read exactly.

    Refused rather than partially read, for the reason every other loader here
    refuses: a lock understood in part is a gate that passes on the part it
    understood, and a gate that passes for the wrong reason is worse than no gate.
    """
    if not isinstance(raw, dict):
        raise PackError(f"invalid lock {source}: the file must be a mapping")
    version = raw.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise PackError(f"invalid lock {source}: schema_version is required and must be an integer")
    if version > LOCK_SCHEMA_VERSION:
        # Regenerating here would overwrite a teammate's lock with an older layout.
        raise PackError(
            f"invalid lock {source}: schema_version {version} was written by a newer "
            f"Guardana than this build, which reads up to {LOCK_SCHEMA_VERSION} — upgrade "
            f"Guardana to check it"
        )
    if version not in _READABLE_LOCK_SCHEMAS:
        readable = " or ".join(str(v) for v in sorted(_READABLE_LOCK_SCHEMAS))
        raise PackError(
            f"invalid lock {source}: schema_version {version} is not a version this "
            f"build reads ({readable}) — regenerate it with `guardana pack lock`"
        )
    packs = raw.get("packs")
    if not isinstance(packs, list):
        raise PackError(f"invalid lock {source}: 'packs' must be a list")
    unlocked = _strings(raw.get("unlocked"), "unlocked", source)
    if version < LOCK_SCHEMA_VERSION and any(_is_output_id(i) for i in unlocked):
        raise PackError(
            f"invalid lock {source}: schema {version} cannot list an output in 'unlocked' — "
            f"a lock naming an output is schema {LOCK_SCHEMA_VERSION}"
        )
    read = tuple(_pack(entry, source, version) for entry in packs)
    _refuse_shared_names(
        ((p.name, p.distribution) for p in read), f"invalid lock {source}: its packs"
    )
    return Lock(
        packs=read,
        unlocked=unlocked,
        # Schema 1 differs from 2 only in layout, and 2 is still written when no
        # output is pinned, so only schema 1 is a migration.
        schema_version=max(version, _SCHEMA_WITHOUT_OUTPUTS),
        extension_api=_api(raw.get("extension_api"), source),
        migrated_from=version if version < _SCHEMA_WITHOUT_OUTPUTS else None,
    )


def incomparable(locked: Lock, installed: Lock) -> str | None:
    """Why these two locks cannot be compared at all, or None when they can.

    Asked before `compare`, because this is not a difference between two builds —
    it is the two builds not sharing the vocabulary a difference would be expressed
    in. `Rule.digest()` covers the fields of `RuleMeta`, and `extension_api` moving
    is precisely what changes those fields, so a digest taken under one contract and
    one taken under another are not the same measurement even when they are equal.

    This is the comparison `_api` refuses a lock without the field *for*. It was
    required on read from the first release and read by nothing, so a lock taken
    against another contract reported every pack as matching.

    Reported as a refusal rather than as drift: every rule would come back `changed`
    with a detail naming the wrong cause, and the answer to all of them is the one
    sentence below.
    """
    if locked.extension_api != installed.extension_api:
        return (
            f"the lock was taken against extension_api {locked.extension_api} and this "
            f"build implements {installed.extension_api}, so what it pins was measured "
            f"under a different contract — regenerate it with `guardana pack lock`"
        )
    return None


def compare(locked: Lock, installed: Lock) -> tuple[Drift, ...]:
    """Every way what is installed differs from what was locked.

    Both directions, always. A missing rule is coverage a team still believes they
    have; an added one is a check nobody reviewed running against production. Only
    reporting the first would make the lock a floor rather than a pin. Either side
    naming one pack twice raises `PackError`, as `lock_of` and `lock_from_dict` do.
    """
    _refuse_shared_names(((p.name, p.distribution) for p in locked.packs), "locked packs")
    _refuse_shared_names(((p.name, p.distribution) for p in installed.packs), "installed packs")
    drift: list[Drift] = []
    by_name = {pack.name: pack for pack in installed.packs}
    for pack in locked.packs:
        present = by_name.get(pack.name)
        if present is None:
            drift.append(
                Drift(
                    DriftKind.PACK_MISSING,
                    pack.name,
                    f"locked at {pack.distribution} {pack.version} and not installed, so every "
                    f"check it provides is missing from this run",
                )
            )
            continue
        drift.extend(_pack_drift(pack, present))
    for name in sorted(set(by_name) - {pack.name for pack in locked.packs}):
        pack = by_name[name]
        drift.append(
            Drift(
                DriftKind.PACK_UNLOCKED,
                name,
                f"{pack.distribution} {pack.version} is installed and the lock does not "
                f"mention it — a pack nobody pinned is running here",
            )
        )
    drift.extend(_membership(locked.unlocked, installed.unlocked, "extension outside any pack"))
    return tuple(drift)


def _pack_drift(locked: LockedPack, installed: LockedPack) -> list[Drift]:
    drift: list[Drift] = []
    if locked.distribution != installed.distribution:
        drift.append(
            Drift(
                DriftKind.DISTRIBUTION_CHANGED,
                locked.name,
                f"locked as shipped by {locked.distribution}, installed from "
                f"{installed.distribution} — the code behind its ids is not the code pinned",
            )
        )
    if locked.version != installed.version:
        drift.append(
            Drift(
                DriftKind.VERSION_CHANGED,
                locked.name,
                f"locked at {locked.version}, installed {installed.version}",
            )
        )
    drift.extend(_digests(locked.name, locked.rules, installed.rules, "rule"))
    drift.extend(_digests(locked.name, locked.taxonomies, installed.taxonomies, "catalogue"))
    drift.extend(_membership(locked.evaluators, installed.evaluators, "evaluator"))
    drift.extend(_membership(locked.targets, installed.targets, "target"))
    drift.extend(_membership(locked.renderers, installed.renderers, "renderer"))
    drift.extend(_membership(locked.reporters, installed.reporters, "reporter"))
    return drift


def _digests(
    pack: str, locked: Mapping[str, str], installed: Mapping[str, str], what: str
) -> list[Drift]:
    return [
        *_membership(tuple(locked), tuple(installed), what, pack),
        *(
            Drift(
                DriftKind.CHANGED,
                name,
                f"{what} is pinned at {locked[name]} and this build has "
                f"{installed[name]} — it is not the same check any more",
            )
            for name in sorted(set(locked) & set(installed))
            if locked[name] != installed[name]
        ),
    ]


def _membership(
    locked: Sequence[str], installed: Sequence[str], what: str, pack: str = ""
) -> list[Drift]:
    owner = f" by {pack}" if pack else ""
    return [
        *(
            Drift(DriftKind.REMOVED, name, f"{what} was locked{owner} and is gone")
            for name in sorted(set(locked) - set(installed))
        ),
        *(
            Drift(DriftKind.ADDED, name, f"{what} is installed and was never locked")
            for name in sorted(set(installed) - set(locked))
        ),
    ]


def _nested(digests: Mapping[str, str]) -> dict[str, dict[str, str]]:
    return {name: {"digest": digest} for name, digest in sorted(digests.items())}


def _pack(raw: object, source: str, schema: int) -> LockedPack:
    if not isinstance(raw, dict):
        raise PackError(f"invalid lock {source}: every entry in 'packs' must be a mapping")
    if schema < LOCK_SCHEMA_VERSION:
        if "renderers" in raw or "reporters" in raw:
            # Refused rather than read: a build that predates outputs reads the same
            # file and ignores the keys, so the version no longer describes it.
            raise PackError(
                f"invalid lock {source}: schema {schema} has no 'renderers' or "
                f"'reporters' — a lock pinning an output is schema {LOCK_SCHEMA_VERSION}"
            )
        renderers: tuple[str, ...] = ()
        reporters: tuple[str, ...] = ()
    else:
        renderers = _required_strings(raw, "renderers", source)
        reporters = _required_strings(raw, "reporters", source)
    return LockedPack(
        name=_text(raw, "name", source),
        distribution=_text(raw, "distribution", source),
        version=_text(raw, "version", source),
        rules=_digest_map(raw.get("rules"), "rules", source, schema),
        evaluators=_strings(raw.get("evaluators"), "evaluators", source),
        targets=_strings(raw.get("targets"), "targets", source),
        taxonomies=_digest_map(raw.get("taxonomies"), "taxonomies", source, schema),
        renderers=renderers,
        reporters=reporters,
    )


def _digest_map(raw: object, key: str, source: str, schema: int) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not all(isinstance(name, str) for name in raw):
        raise PackError(f"invalid lock {source}: '{key}' must map every id to a digest")
    if schema == 1:
        if not all(isinstance(value, str) for value in raw.values()):
            raise PackError(
                f"invalid lock {source}: schema 1 '{key}' must map every id to a digest string"
            )
        return dict(raw)
    if not all(
        isinstance(value, dict) and set(value) == {"digest"} and isinstance(value["digest"], str)
        for value in raw.values()
    ):
        raise PackError(
            f"invalid lock {source}: '{key}' must map every id to exactly {{digest: <string>}}"
        )
    return {name: value["digest"] for name, value in raw.items()}


def _strings(raw: object, key: str, source: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PackError(f"invalid lock {source}: '{key}' must be a list of strings")
    return tuple(raw)


def _required_strings(raw: dict[str, Any], key: str, source: str) -> tuple[str, ...]:
    if key not in raw:
        raise PackError(
            f"invalid lock {source}: every schema {LOCK_SCHEMA_VERSION} pack lists '{key}', "
            f"even when empty"
        )
    return _strings(raw[key], key, source)


def _text(raw: dict[str, Any], key: str, source: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PackError(f"invalid lock {source}: every pack needs a non-empty '{key}'")
    return value


def _api(raw: object, source: str) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise PackError(
            f"invalid lock {source}: 'extension_api' is required and must be an integer — "
            f"a lock that does not say which contract it was taken against cannot be "
            f"compared against a build that implements a different one"
        )
    return raw
