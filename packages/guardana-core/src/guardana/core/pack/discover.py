"""Find installed pack manifests, and check each against what its package registers.

A manifest is a claim; this is where the claim meets the registry. The direction
that matters is the *missing* one: a pack promising `acme.agent.customer_data` and
not registering it leaves a team believing a check runs that never does — which is
the same false green the engine refuses everywhere else, arriving through
documentation instead of through code.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib import metadata, resources

from guardana.core.entrypoints import (
    GROUPS,
    OUTPUT_GROUPS,
    InstalledEntryPoint,
    installed_entry_points,
)
from guardana.core.pack.load import MANIFEST_NAME, load_manifest
from guardana.core.pack.model import (
    SUPPORTED_EXTENSION_API_VERSIONS,
    PackError,
    PackManifest,
    output_id,
)
from guardana.core.plugins import PluginTrust


@dataclass(frozen=True, slots=True)
class PackCheck:
    """One pack, and everything wrong with it — or nothing."""

    manifest: PackManifest
    problems: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Whether this pack is loadable and describes itself accurately."""
        return not self.problems


@dataclass(frozen=True, slots=True)
class Registered:
    """What a build registers, by kind, with the distribution that registered each id.

    A distribution of `None` is one the registry cannot name — an id registered in
    code, or a kind whose origin it does not record. Such an id cannot be shown to
    belong to the pack that claims it, so a pack whose distribution is known fails on
    it; a manifest given by path is checked by kind only.
    """

    rules: Mapping[str, str | None] = field(default_factory=dict)
    evaluators: Mapping[str, str | None] = field(default_factory=dict)
    targets: Mapping[str, str | None] = field(default_factory=dict)
    taxonomies: Mapping[str, str | None] = field(default_factory=dict)
    taxonomy_owners: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """Every distribution that registered a reference into each framework.

    A framework is shared — a pack may add controls to a built-in one — so it can
    have several owners, and a pack's claim to it holds when the pack is among them.
    """

    renderers: Mapping[str, str | None] = field(default_factory=dict)
    """Every installed format that can be selected, by name."""

    reporters: Mapping[str, str | None] = field(default_factory=dict)
    """Every installed reporter that can be selected, by name."""

    output_collisions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """`renderer:<name>` or `reporter:<name>`, to each distribution installing it.

    A name installed by several distributions can never be selected, so a pack
    declaring it promises an output no run will use.
    """


@dataclass(frozen=True, slots=True)
class PackDiscovery:
    """The installed packs trust admits, and the entry points it kept closed.

    Returned together so a caller cannot report on the admitted packs without the
    refusals in hand: a subset that does not say it is one reads as the whole.
    """

    packs: tuple[tuple[str, str, PackManifest], ...]
    """Every admitted pack as `(distribution, version, manifest)`."""

    unmanifested: tuple[str, ...]
    """Every admitted module that registers an extension and declares no manifest."""

    refused: tuple[InstalledEntryPoint, ...]
    """Every entry point trust refused; its module was never imported to look for a manifest."""

    @property
    def manifests(self) -> tuple[PackManifest, ...]:
        """The manifest of every admitted pack."""
        return tuple(manifest for _distribution, _version, manifest in self.packs)


def discover_packs(trust: PluginTrust) -> PackDiscovery:
    """Read the manifest of every installed package whose entry points `trust` admits.

    Trust is decided per entry point, over the enumeration `Registry.discover` walks
    plus the two output groups: a module is read only when an admitted entry point
    names it, because reading a manifest through `importlib.resources` imports the
    module.

    **Located from the entry point, not from the distribution's file list.** An
    editable install lists no files, so walking them finds nothing for a package
    sitting right there. The entry point names the module that provides the
    extension, and that module's package is exactly the one that owns the manifest.

    **The distribution is taken from the entry point**, not from
    `packages_distributions()`: `guardana` is a PEP 420 namespace shared by five
    distributions, so a top-level-name lookup answers with whichever sorts first. A
    module whose distribution cannot be resolved is still returned, named by its
    module and with an empty version, because a pack silently missing from a lock is
    a pack running unpinned.
    """
    if not isinstance(trust, PluginTrust):
        raise TypeError(f"discover_packs needs a PluginTrust, not {type(trust).__name__}")
    owners: dict[str, tuple[str, str | None]] = {}
    modules: set[str] = set()
    refused: list[InstalledEntryPoint] = []
    for entry_point in installed_entry_points(groups=(*GROUPS, *OUTPUT_GROUPS)):
        if not trust.allows(entry_point.distribution):
            refused.append(entry_point)
            continue
        if not entry_point.module:
            continue
        modules.add(entry_point.module)
        if entry_point.distribution is not None:
            owners.setdefault(entry_point.module, (entry_point.distribution, entry_point.version))
    packs: list[tuple[str, str, PackManifest]] = []
    unmanifested: list[str] = []
    for module in sorted(modules):
        manifest = _manifest_in(module)
        if manifest is None:
            unmanifested.append(module)
            continue
        distribution, version = owners.get(module, (module, None))
        packs.append((distribution, version or _version(distribution), manifest))
    return PackDiscovery(tuple(packs), tuple(unmanifested), tuple(refused))


def installed_packs(trust: PluginTrust) -> list[tuple[str, str, PackManifest]]:
    """Every installed pack `trust` admits, as `(distribution, version, manifest)`.

    What trust refused is not in this list; `discover_packs` returns it beside the
    packs, and a caller passing a trust other than `all` reads it there.
    """
    return list(discover_packs(trust).packs)


def installed_manifests(trust: PluginTrust) -> list[PackManifest]:
    """Return the manifest of every installed extension package `trust` admits.

    **Not de-duplicated by declared name.** Two packs claiming one name is a real
    situation — a fork, a rename half-done — and dropping the second would silently
    stop validating somebody's pack; `check_packs` reports it and validates both.

    What trust refused is not in this list; `discover_packs` returns it beside the
    manifests.
    """
    return list(discover_packs(trust).manifests)


def unmanifested_packages(trust: PluginTrust) -> list[str]:
    """Every admitted package that registers an extension and declares no manifest.

    The other half of `installed_manifests`: those packages are live in the registry
    and invisible to every check that reads manifests. A caller that reports only the
    manifests it found is reporting on a subset it cannot name the size of.
    """
    return list(discover_packs(trust).unmanifested)


def _version(distribution: str) -> str:
    """Return the installed version, or an empty string when the metadata cannot say.

    Empty rather than omitted: a pack whose version cannot be read is still pinned by
    the digests of what it registers, and dropping it from the lock over a metadata
    problem would leave it running unpinned.
    """
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return ""


def check_packs(
    manifests: Sequence[PackManifest],
    registered: Registered,
    distributions: Sequence[str | None] | None = None,
) -> list[PackCheck]:
    """Check every pack, and report two of them claiming one name.

    `distributions`, when given, names the distribution shipping each manifest, in
    the same order. A manifest name is how a person identifies a pack in the output,
    so two packs answering to it makes the report ambiguous about which one was
    checked — and an ambiguous report about a security control is the thing somebody
    acts on wrongly.
    """
    registered = _require_registered(registered)
    owners = list(distributions) if distributions is not None else [None] * len(manifests)
    if len(owners) != len(manifests):
        raise ValueError("check_packs needs one distribution per manifest")
    counts = Counter(manifest.name for manifest in manifests)
    checks = []
    for manifest, distribution in zip(manifests, owners, strict=True):
        check = check_pack(manifest, registered, distribution)
        if counts[manifest.name] > 1:
            check = PackCheck(
                manifest,
                (
                    *check.problems,
                    f"{counts[manifest.name]} installed packs declare the name "
                    f"{manifest.name!r} — a report naming one of them cannot say which",
                ),
            )
        checks.append(check)
    return checks


def check_pack(
    manifest: PackManifest,
    registered: Registered,
    distribution: str | None = None,
) -> PackCheck:
    """Compare one manifest against the ids actually registered, and against this build.

    Two questions, and both have to be answered before a pack is a safe investment:
    *can this build load it at all*, and *does it do what its manifest says*. Each
    declared id is looked up under its own kind, and, when `distribution` names the
    one shipping the manifest, it must be that distribution that registers it — for a
    framework, one of the distributions registering into it: an id another pack
    supplies disappears with that pack while this manifest still promises it, and an
    id no distribution can be named for is not shown to be this pack's either.
    """
    registered = _require_registered(registered)
    problems: list[str] = []
    if not manifest.loadable_by():
        problems.append(manifest.extension_api.why_not_any(SUPPORTED_EXTENSION_API_VERSIONS))
    problems.extend(_output_api_problems(manifest))
    problems.extend(_collision_problems(manifest, registered.output_collisions))
    groups: tuple[tuple[str, Sequence[str], Mapping[str, str | None], _Owners], ...] = (
        ("rule", manifest.rules, registered.rules, {}),
        ("evaluator", manifest.evaluators, registered.evaluators, {}),
        ("target", manifest.targets, registered.targets, {}),
        ("taxonomy", manifest.taxonomies, registered.taxonomies, registered.taxonomy_owners),
        (
            "renderer",
            _selectable("renderer", manifest.renderers, registered),
            registered.renderers,
            {},
        ),
        (
            "reporter",
            _selectable("reporter", manifest.reporters, registered),
            registered.reporters,
            {},
        ),
    )
    for kind, declared, present, shared in groups:
        missing = [i for i in declared if i not in present]
        if missing:
            problems.append(
                f"declares {kind} {', '.join(missing)} and does not register "
                f"{_it(missing)} — a team reading this manifest believes a check runs "
                f"that does not"
            )
        if distribution is None:
            continue
        foreign = [
            f"{i} ({_registered_by(owners)})"
            for i in declared
            if i in present and distribution not in (owners := _owners(i, present, shared))
        ]
        if foreign:
            problems.append(
                f"declares {kind} {', '.join(foreign)} and does not register "
                f"{_it(foreign)} itself — a team reading this manifest believes this pack "
                f"provides a check that another distribution supplies"
            )
    return PackCheck(manifest, tuple(problems))


_Owners = Mapping[str, frozenset[str]]


def _output_api_problems(manifest: PackManifest) -> list[str]:
    """Say why this build cannot run the pack's outputs, in the words `why_not_any` uses."""
    # Imported here: `guardana.core.output` reaches `verify`, which imports this
    # package, so a module-level import is a cycle.
    from guardana.core.output import SUPPORTED_OUTPUT_API_VERSIONS  # noqa: PLC0415

    if manifest.outputs_loadable_by(SUPPORTED_OUTPUT_API_VERSIONS):
        return []
    if manifest.output_api is None:
        return [
            "declares a renderer or reporter and no output_api, so nothing says which "
            "output contract it was written against"
        ]
    return [manifest.output_api.why_not_any(SUPPORTED_OUTPUT_API_VERSIONS, what="output API")]


def _collision_problems(
    manifest: PackManifest, collisions: Mapping[str, tuple[str, ...]]
) -> list[str]:
    """Every declared output that several distributions install, which no run can select."""
    return [
        f"declares {kind} {name}, which {len(found)} distributions provide "
        f"({', '.join(found)}) — selecting it is refused"
        for kind, names in (("renderer", manifest.renderers), ("reporter", manifest.reporters))
        for name in names
        if (found := collisions.get(output_id(kind, name)))
    ]


def _selectable(kind: str, names: Sequence[str], registered: Registered) -> tuple[str, ...]:
    """Keep the declared outputs not in a collision, which `_collision_problems` reports."""
    collided = registered.output_collisions
    return tuple(name for name in names if output_id(kind, name) not in collided)


def _owners(identifier: str, present: Mapping[str, str | None], shared: _Owners) -> frozenset[str]:
    """Every distribution the registry names for `identifier`; empty when it can name none."""
    single = present.get(identifier)
    return shared.get(identifier, frozenset()) | ({single} if single is not None else set())


def _registered_by(owners: frozenset[str]) -> str:
    if not owners:
        return "registered by no distribution this build can name"
    return f"registered by {', '.join(sorted(owners))}"


def _require_registered(registered: Registered) -> Registered:
    """Refuse anything but a `Registered`, which names each id's kind and distribution."""
    if not isinstance(registered, Registered):
        raise TypeError(
            "check_pack and check_packs take a Registered; a flat set of ids is no longer accepted"
        )
    return registered


def _it(ids: Sequence[str]) -> str:
    return "it" if len(ids) == 1 else "them"


def _manifest_in(package: str) -> PackManifest | None:
    """Read the manifest a package ships, or None when it ships none.

    Absent is allowed, and reported. Requiring one would make every pack written
    before this existed unloadable — breaking somebody's package to enforce a bar it
    could not have known about. Dropping it silently would be worse: the extension
    stays live in the registry while the command that judges packs never mentions
    it, so `unmanifested_packages` is what keeps the absence visible.
    """
    try:
        candidate = resources.files(package).joinpath(MANIFEST_NAME)
        if not candidate.is_file():
            return None
        with resources.as_file(candidate) as path:
            return load_manifest(path)
    except ImportError as exc:
        if isinstance(exc, ModuleNotFoundError) and _names_itself(exc.name, package):
            return None
        # The package exists and cannot be imported, so whether it ships a manifest
        # is unknown; reporting it as declaring none would be a guess.
        raise PackError(
            f"cannot read the manifest of {package}: importing it failed with "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    except (TypeError, OSError):
        return None
    except PackError:
        # A manifest that is present and unreadable is a real problem, and swallowing
        # it here would report the pack as having declared nothing. Raised so the
        # command exits `3` naming the file, exactly as a malformed contract does.
        raise


def _names_itself(missing: str | None, package: str) -> bool:
    """Whether the module that could not be found is `package` or one of its parents."""
    return missing is not None and (package == missing or package.startswith(f"{missing}."))
