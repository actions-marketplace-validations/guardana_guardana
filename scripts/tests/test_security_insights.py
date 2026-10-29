"""security-insights.yml is valid OpenSSF Security Insights v2.2.0 and claims only what ships.

The spec publishes its v2.2.0 schema as CUE only
(https://github.com/ossf/security-insights-spec/blob/v2.2.0/spec/schema.cue, no JSON
Schema release asset), so the definitions the file uses are mirrored here: every
required field, every optional one, and the value formats. CUE definitions are closed,
so an unknown key is a violation as well. The facts are then checked against the
sources they come from: SECURITY.md, the package metadata and the SBOM script.
"""

from __future__ import annotations

import copy
import datetime
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

import generate_sbom

_ROOT = Path(__file__).resolve().parents[2]
DOC = yaml.safe_load((_ROOT / "security-insights.yml").read_text(encoding="utf-8"))

Check = Callable[[object, str], list[str]]


def _leaf(accepts: Callable[[object], bool], what: str) -> Check:
    def check(value: object, path: str) -> list[str]:
        return [] if accepts(value) else [f"{path}: {value!r} is not {what}"]

    return check


def _matches(pattern: str) -> Callable[[object], bool]:
    compiled = re.compile(pattern)
    return lambda value: isinstance(value, str) and compiled.match(value) is not None


def _is_date(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


_STRING = _leaf(lambda value: isinstance(value, str), "a string")
_BOOL = _leaf(lambda value: isinstance(value, bool), "a bool")
_URL = _leaf(_matches(r"^https?://[^\s]+$"), "a URL")
_EMAIL = _leaf(_matches(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"), "an email")
_DATE = _leaf(_is_date, "a YYYY-MM-DD date")
_SCHEMA_VERSION = _leaf(_matches(r"^[1-9]+\.[0-9]+\.[0-9]+$"), "an X.Y.Z version")


def _one_of(*allowed: str) -> Check:
    return _leaf(lambda value: value in allowed, f"one of {allowed}")


def _list(item: Check, *, minimum: int = 0) -> Check:
    def check(value: object, path: str) -> list[str]:
        if not isinstance(value, list) or len(value) < minimum:
            return [f"{path}: not a list of at least {minimum}"]
        return [
            problem
            for index, each in enumerate(value)
            for problem in item(each, f"{path}[{index}]")
        ]

    return check


def _object(required: dict[str, Check], optional: dict[str, Check] | None = None) -> Check:
    """A closed CUE definition: each required key present, no key outside the two sets."""
    allowed = {**required, **(optional or {})}

    def check(value: object, path: str) -> list[str]:
        if not isinstance(value, dict):
            return [f"{path}: not an object"]
        problems = [f"{path}.{key}: required" for key in required if key not in value]
        problems += [f"{path}.{key}: not in the schema" for key in value if key not in allowed]
        problems += [
            problem
            for key, each in value.items()
            if key in allowed
            for problem in allowed[key](each, f"{path}.{key}")
        ]
        return problems

    return check


_CONTACT = _object(
    {"name": _STRING, "primary": _BOOL},
    {"affiliation": _STRING, "email": _EMAIL, "social": _STRING},
)
_ATTESTATION = _object(
    {"name": _STRING, "location": _URL, "predicate-uri": _STRING}, {"comment": _STRING}
)
_LICENSE = _object({"url": _URL, "expression": _STRING})
_LINK = _object({"uri": _STRING, "comment": _STRING})
_ASSESSMENT = _object({"comment": _STRING}, {"name": _STRING, "evidence": _URL, "date": _DATE})
_HEADER = _object(
    {"last-reviewed": _DATE, "last-updated": _DATE, "schema-version": _SCHEMA_VERSION, "url": _URL},
    {"comment": _STRING, "project-si-source": _URL},
)
_PROJECT_DOCUMENTATION = _object(
    {},
    dict.fromkeys(
        (
            "design",
            "detailed-guide",
            "code-of-conduct",
            "quickstart-guide",
            "release-process",
            "support-policy",
            "signature-verification",
        ),
        _URL,
    ),
)
_VULNERABILITY_REPORTING = _object(
    {"reports-accepted": _BOOL, "bug-bounty-available": _BOOL},
    {
        "bug-bounty-program": _URL,
        "contact": _CONTACT,
        "comment": _STRING,
        "policy": _URL,
        "pgp-key": _STRING,
        "in-scope": _list(_STRING),
        "out-of-scope": _list(_STRING),
    },
)
_PROJECT = _object(
    {
        "name": _STRING,
        "administrators": _list(_CONTACT, minimum=1),
        "repositories": _list(
            _object({"name": _STRING, "comment": _STRING, "url": _URL}), minimum=1
        ),
        "vulnerability-reporting": _VULNERABILITY_REPORTING,
    },
    {
        "homepage": _URL,
        "roadmap": _URL,
        "funding": _URL,
        "steward": _LINK,
        "documentation": _PROJECT_DOCUMENTATION,
    },
)
_SECURITY_TOOL = _object(
    {
        "name": _STRING,
        "type": _one_of("fuzzing", "container", "secret", "SCA", "SAST", "other"),
        "rulesets": _list(_STRING),
        "integration": _object({"adhoc": _BOOL, "ci": _BOOL, "release": _BOOL}),
        "results": _object(
            {}, {"adhoc": _ATTESTATION, "ci": _ATTESTATION, "release": _ATTESTATION}
        ),
    },
    {"version": _STRING, "comment": _STRING},
)
_SECURITY_POSTURE = _object(
    {"assessments": _object({"self": _ASSESSMENT}, {"third-party": _list(_ASSESSMENT)})},
    {"champions": _list(_CONTACT), "tools": _list(_SECURITY_TOOL)},
)
_REPOSITORY = _object(
    {
        "status": _one_of(
            "active", "abandoned", "concept", "inactive", "moved", "suspended", "unsupported", "WIP"
        ),
        "url": _URL,
        "accepts-change-request": _BOOL,
        "accepts-automated-change-request": _BOOL,
        "core-team": _list(_CONTACT, minimum=1),
        "license": _LICENSE,
        "security": _SECURITY_POSTURE,
    },
    {
        "bug-fixes-only": _BOOL,
        "no-third-party-packages": _BOOL,
        "documentation": _object(
            {},
            dict.fromkeys(
                (
                    "contributing-guide",
                    "dependency-management-policy",
                    "governance",
                    "review-policy",
                    "security-policy",
                ),
                _URL,
            ),
        ),
        "release": _object(
            {"automated-pipeline": _BOOL, "distribution-points": _list(_LINK, minimum=1)},
            {"changelog": _URL, "license": _LICENSE, "attestations": _list(_ATTESTATION)},
        ),
    },
)
_SECURITY_INSIGHTS = _object({"header": _HEADER}, {"project": _PROJECT, "repository": _REPOSITORY})


def test_the_file_is_valid_against_the_v2_2_0_schema() -> None:
    assert DOC["header"]["schema-version"] == "2.2.0"
    assert _SECURITY_INSIGHTS(DOC, "") == []


def _without(path: tuple[str, ...]) -> object:
    broken = copy.deepcopy(DOC)
    parent = broken
    for key in path[:-1]:
        parent = parent[key]
    del parent[path[-1]]
    return broken


def _with(path: tuple[str, ...], value: object) -> object:
    broken = copy.deepcopy(DOC)
    parent = broken
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    return broken


@pytest.mark.parametrize(
    "broken",
    [
        _without(("project", "administrators")),
        _with(("project", "administrators"), []),
        _without(("project", "vulnerability-reporting", "bug-bounty-available")),
        _without(("repository", "security")),
        _with(("project", "documentation", "governance"), "https://example.org/governance"),
        _with(("project", "administrators"), [{"name": "A", "primary": True, "email": "no"}]),
        _with(("repository", "release", "distribution-points"), [{"uri": "pkg:pypi/x"}]),
        _with(("header", "last-updated"), "2026-13-01"),
    ],
    ids=[
        "no-administrators",
        "empty-administrators",
        "no-bug-bounty-flag",
        "no-security-posture",
        "governance-under-project",
        "malformed-email",
        "link-without-comment",
        "impossible-date",
    ],
)
def test_the_mirrored_schema_refuses_what_the_spec_refuses(broken: object) -> None:
    assert _SECURITY_INSIGHTS(broken, "") != []


def test_vulnerability_reporting_matches_security_md() -> None:
    reporting = DOC["project"]["vulnerability-reporting"]
    assert reporting["reports-accepted"] is True
    assert urlparse(reporting["policy"]).path == "/guardana/guardana/blob/main/SECURITY.md"
    security_md = (_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert reporting["contact"]["email"] in security_md


def test_the_homepage_is_the_one_the_packages_declare() -> None:
    metadata = tomllib.loads(
        (_ROOT / "packages" / "guardana-core" / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert DOC["project"]["homepage"] == metadata["project"]["urls"]["Homepage"]


def _hosted(url: str) -> tuple[str | None, str]:
    parsed = urlparse(url)
    return parsed.hostname, parsed.path


def test_release_artifacts_are_the_ones_the_release_workflow_publishes() -> None:
    release = DOC["repository"]["release"]
    attestations = {_hosted(a["predicate-uri"]): a for a in release["attestations"]}
    sbom = attestations[("cyclonedx.org", "/bom")]
    assert _hosted(sbom["location"]) == ("github.com", "/guardana/guardana/releases")
    assert generate_sbom._FORMAT == "cyclonedx1.5"
    assert "CycloneDX 1.5" in sbom["comment"]
    assert "attestation verify" not in sbom["comment"]
    provenance = attestations[("slsa.dev", "/provenance/v1")]
    assert _hosted(provenance["location"]) == ("github.com", "/guardana/guardana/attestations")
    uris = {point["uri"] for point in release["distribution-points"]}
    pypi = {uri for uri in uris if uri.startswith("pkg:pypi/")}
    assert pypi == {f"pkg:pypi/{name}" for name in generate_sbom._PACKAGES}
    assert {"ghcr.io/guardana/guardana", "ghcr.io/guardana/guardana-collector"} <= uris
    assert ("github.com", "/guardana/guardana/releases") in {_hosted(uri) for uri in uris}
