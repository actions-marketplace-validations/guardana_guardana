"""The bundled, offline advisory dataset behind `malicious_dependency`.

Deliberately *not* a general CVE feed — that is well served elsewhere and is an
explicit non-goal. An entry earns its place only by closing the loop between an
artifact Guardana already finds and the code that would execute it:

* `malicious_release` — a confirmed compromised or dependency-confusion release.
  The exact (name, version) pair is the evidence, and it is the one signal that
  catches a *legitimate* package which was poisoned: it passes every
  "unknown import" and "unpinned download" check ever written.
* `vulnerable_loader` — a library whose vulnerability *arms* an artifact finding.
  A poisoned chat template is inert without a renderer that executes it; a
  `_attn_implementation_internal` field is inert without a transformers that
  dispatches it. This channel says "the loader on your dependency list is the
  one that makes the file we found dangerous".

The dataset is validated at load time and fails loudly: a blocklist that quietly
loads as empty is a rubber stamp, which is worse than no blocklist at all.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from importlib.resources import as_file, files
from pathlib import Path

from guardana.core.rule import RuleLoadError
from guardana.core.severity import Severity
from guardana.rules.supply_chain._versions import Version, parse_version

SCHEMA_VERSION = 1
ADVISORY_KINDS = frozenset({"malicious_release", "vulnerable_loader"})
_REQUIRED_FIELDS = frozenset(
    {"id", "package", "kind", "versions", "severity", "summary", "reference"}
)
_BUNDLED = "advisories/ml_advisories.json"
_ANY_VERSION = "*"
_COMPARATORS = ("<=", ">=", "<", ">")


@dataclass(frozen=True)
class Advisory:
    """One sourced advisory about a package release in the AI/ML stack."""

    id: str
    package: str
    kind: str
    versions: tuple[str, ...]
    severity: Severity
    summary: str
    reference: str

    def matches(self, version: str, *, arbitrary: bool = False) -> bool:
        """Whether this advisory covers the given pinned version (`===` when `arbitrary`)."""
        return any(version_matches(spec, version, arbitrary=arbitrary) for spec in self.versions)


def load_advisories(path: Path | None = None) -> tuple[Advisory, ...]:
    """Load and validate an advisory dataset; the bundled one when `path` is None.

    Raises `RuleLoadError` on anything it cannot fully understand — a typo'd key,
    an unknown kind, an unreadable file. Silence here would disarm the rule.
    """
    if path is None:
        with as_file(files("guardana.rules.catalog").joinpath(_BUNDLED)) as bundled:
            return load_advisories(bundled)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuleLoadError(f"cannot read the advisory dataset {path}: {exc}") from exc
    return tuple(_parse(document, path))


def version_matches(spec: str, version: str, *, arbitrary: bool = False) -> bool:
    """Whether a pinned `version` satisfies one advisory spec.

    Supports `*`, an exact version, a comparator (`<`, `<=`, `>`, `>=`), and a
    comma-joined conjunction of comparators. An exact spec matches under PEP 440
    version equality, so `8.3.041` and `8.3.41.0` are the release `8.3.41`; a
    local label on the pin is still the same public release and matches. With
    `arbitrary`, the pin came from `===` and an exact spec is compared as a
    string, as pip does. A version this cannot parse never matches: guessing at
    it would invent a finding.
    """
    if spec == _ANY_VERSION:
        return True
    if not any(spec.startswith(comparator) for comparator in _COMPARATORS):
        if arbitrary:
            return spec.strip().lower() == version.strip().lower()
        return _equal(spec, version)
    parsed = parse_version(version)
    if parsed is None:
        return False
    return all(_clause_matches(clause.strip(), parsed.public) for clause in spec.split(","))


def _equal(spec: str, version: str) -> bool:
    wanted = parse_version(spec)
    pinned = parse_version(version)
    if wanted is None or pinned is None:
        # Two spellings PEP 440 cannot read are only the same version when they are
        # the same text.
        return spec.strip().lower() == version.strip().lower()
    return pinned == wanted if wanted.local is not None else pinned.public == wanted


def _clause_matches(clause: str, version: Version) -> bool:
    for comparator in _COMPARATORS:
        if clause.startswith(comparator):
            bound = parse_version(clause[len(comparator) :])
            if bound is None or bound.local is not None:
                return False
            return _compare(comparator, version, bound)
    return False


def _compare(comparator: str, version: Version, bound: Version) -> bool:
    # PEP 440 excludes `2.6.0rc1` from `<2.6.0` and `2.6.0.post1` from `>2.6.0`, unless
    # the bound is itself a pre- or post-release.
    left, right = version.sort_key(), bound.sort_key()
    if comparator == "<" and not _is_pre(bound) and _is_pre(version):
        earliest = replace(bound, pre=None, dev=0, local=None)
        if left >= earliest.sort_key():
            return False
    if (
        comparator == ">"
        and bound.post is None
        and version.post is not None
        and replace(version, post=None, dev=None, local=None) == bound
    ):
        return False
    if comparator == "<":
        return left < right
    if comparator == "<=":
        return left <= right
    if comparator == ">":
        return left > right
    return left >= right


def _is_pre(version: Version) -> bool:
    """Whether PEP 440 calls `version` a pre-release: it carries a pre- or dev-release marker."""
    return version.pre is not None or version.dev is not None


def _parse(document: object, path: Path) -> list[Advisory]:
    if not isinstance(document, dict):
        raise RuleLoadError(f"advisory dataset {path} is not a JSON object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise RuleLoadError(
            f"advisory dataset {path}: schema_version must be {SCHEMA_VERSION}, "
            f"got {document.get('schema_version')!r}"
        )
    entries = document.get("advisories")
    if not isinstance(entries, list):
        raise RuleLoadError(f"advisory dataset {path}: 'advisories' must be a list")
    return [_advisory(entry, path) for entry in entries]


def _advisory(entry: object, path: Path) -> Advisory:
    if not isinstance(entry, dict):
        raise RuleLoadError(f"advisory dataset {path}: every advisory must be an object")
    _check_fields(entry, path)
    kind = entry["kind"]
    if kind not in ADVISORY_KINDS:
        raise RuleLoadError(
            f"advisory {entry['id']}: kind must be one of {sorted(ADVISORY_KINDS)}, got {kind!r}"
        )
    versions = entry["versions"]
    if not isinstance(versions, list) or not versions:
        raise RuleLoadError(f"advisory {entry['id']}: 'versions' must be a non-empty list")
    return Advisory(
        id=str(entry["id"]),
        package=str(entry["package"]).lower(),
        kind=str(kind),
        versions=tuple(str(version) for version in versions),
        severity=_severity(entry["severity"], str(entry["id"])),
        summary=str(entry["summary"]),
        reference=str(entry["reference"]),
    )


def _check_fields(entry: Mapping[str, object], path: Path) -> None:
    missing = sorted(_REQUIRED_FIELDS - set(entry))
    if missing:
        raise RuleLoadError(f"advisory dataset {path}: advisory is missing {missing}")
    unknown = sorted(set(entry) - _REQUIRED_FIELDS)
    if unknown:
        raise RuleLoadError(f"advisory {entry['id']}: unknown key(s) {unknown}")


def _severity(value: object, advisory_id: str) -> Severity:
    try:
        return Severity[str(value).upper()]
    except KeyError as exc:
        raise RuleLoadError(f"advisory {advisory_id}: unknown severity {value!r}") from exc
