"""A profile names the schema it was written for, and the published schema describes every key.

A build reads a profile written for a newer one only to refuse it, naming the upgrade:
a key it does not know would otherwise read as a typo, and a setting it cannot honour
as one it applied. The published schema is checked against the loader's own key sets,
so a key added to one and not the other fails here.
"""

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest
import yaml
from guardana.core.plugins import PluginMode
from guardana.core.profile import PRESET_NAMES, Profile, ProfileError, load_profile, preset
from guardana.core.profile import loader as loader_module
from guardana.core.profile.digest import profile_digest
from guardana.core.profile.loader import EVALUATOR_BLOCK_KEYS, PROFILE_SCHEMA_VERSION
from guardana.core.redaction import EvidenceMode
from guardana.core.severity import Severity
from guardana.core.trace.model import Dimension
from jsonschema import Draft202012Validator

_ROOT = Path(__file__).resolve().parents[4]
_SCHEMA = _ROOT / "schemas" / "profile-v1.schema.json"
_HISTORICAL = Path(__file__).resolve().parents[1] / "historical" / "profile"

_BLOCKS: dict[str, frozenset[str]] = {
    "": loader_module._ALLOWED_PROFILE_KEYS,
    "rules": loader_module._ALLOWED_RULES_KEYS,
    "trace": loader_module._ALLOWED_TRACE_KEYS,
    "plugins": loader_module._ALLOWED_PLUGINS_KEYS,
    "fail_on": loader_module._ALLOWED_FAIL_ON_KEYS,
    "budgets": loader_module._ALLOWED_BUDGET_KEYS,
    "privacy": loader_module._ALLOWED_PRIVACY_KEYS,
    "delivery": loader_module._ALLOWED_DELIVERY_KEYS,
    **{f"evaluators.{name}": keys for name, keys in EVALUATOR_BLOCK_KEYS.items()},
}
"""Each key set the loader accepts, by the dotted block that holds it."""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    return loaded


def _block(schema: dict[str, Any], dotted: str) -> dict[str, Any]:
    node = schema
    for part in [p for p in dotted.split(".") if p]:
        node = node["properties"][part]
    return node


def test_a_profile_without_a_version_reads_as_version_one(tmp_path: Path) -> None:
    unversioned = load_profile(_write(tmp_path, "name: t\n"))
    versioned = load_profile(_write(tmp_path, "schema_version: 1\nname: t\n"))

    assert PROFILE_SCHEMA_VERSION == 1
    assert profile_digest(versioned) == profile_digest(unversioned)


def test_the_version_is_not_a_profile_field() -> None:
    assert "schema_version" not in {member.name for member in fields(Profile)}


def test_a_newer_profile_is_refused_naming_the_upgrade(tmp_path: Path) -> None:
    path = _write(tmp_path, "schema_version: 2\n")

    with pytest.raises(ProfileError) as refused:
        load_profile(path)

    assert str(refused.value) == (
        f"invalid profile {path}: profile schema 2 was written by a newer Guardana; "
        f"this build reads schema 1 — upgrade Guardana"
    )


def test_the_version_is_checked_before_unknown_keys(tmp_path: Path) -> None:
    path = _write(tmp_path, "schema_version: 2\nreporting:\n  every: hour\n")

    with pytest.raises(ProfileError, match="written by a newer Guardana"):
        load_profile(path)


@pytest.mark.parametrize("written", ["true", "'1'", "1.0", "[1]", "null"])
def test_a_version_that_is_not_an_integer_is_refused(tmp_path: Path, written: str) -> None:
    path = _write(tmp_path, f"schema_version: {written}\n")

    with pytest.raises(ProfileError) as refused:
        load_profile(path)

    assert str(refused.value) == f"invalid profile {path}: schema_version must be an integer"


@pytest.mark.parametrize("version", [0, -1])
def test_a_version_below_one_does_not_exist(tmp_path: Path, version: int) -> None:
    path = _write(tmp_path, f"schema_version: {version}\n")

    with pytest.raises(ProfileError) as refused:
        load_profile(path)

    assert str(refused.value) == f"invalid profile {path}: schema_version {version} does not exist"


def test_every_key_set_of_the_loader_is_named_here() -> None:
    declared = {
        name
        for name, value in vars(loader_module).items()
        if name.startswith("_ALLOWED_") and isinstance(value, frozenset)
    }
    named = {
        name
        for name in declared
        if any(getattr(loader_module, name) is keys for keys in _BLOCKS.values())
    }

    assert declared == named


@pytest.mark.parametrize("dotted", sorted(_BLOCKS))
def test_the_schema_describes_exactly_the_keys_the_loader_accepts(dotted: str) -> None:
    block = _block(_schema(), dotted)
    accepted = set(_BLOCKS[dotted]) | ({"schema_version"} if dotted == "" else set())

    assert set(block["properties"]) == accepted
    assert block["additionalProperties"] is False


def test_the_schema_names_the_version_this_build_reads() -> None:
    schema = _schema()

    assert schema["properties"]["schema_version"]["const"] == PROFILE_SCHEMA_VERSION
    assert schema["$id"] == (
        f"https://guardana.dev/schemas/profile/v{PROFILE_SCHEMA_VERSION}.schema.json"
    )


def test_the_schema_enumerates_what_the_code_enumerates() -> None:
    schema = _schema()
    privacy = _block(schema, "privacy")["properties"]
    validator = Draft202012Validator(schema)

    assert privacy["evidence_mode"]["enum"] == [str(mode) for mode in EvidenceMode]
    assert _block(schema, "trace")["properties"]["require"]["items"]["enum"] == [
        str(dimension) for dimension in Dimension
    ]
    assert _block(schema, "plugins")["properties"]["mode"]["enum"] == [
        str(mode) for mode in PluginMode
    ]
    for severity in Severity:
        for spelling in (severity.name, severity.name.lower(), severity.name.title()):
            validator.validate({"fail_on": {"severity": spelling}})


@pytest.mark.parametrize(
    "document",
    [
        {"reporting": True},
        {"schema_version": 2},
        {"delivery": {"required": "yes"}},
        {"delivery": {"required": True, "retries": 3}},
        {"fail_on": {"severity": "severe"}},
        {"evaluators": {"llm_judge": {"endpont": "http://judge"}}},
    ],
)
def test_the_schema_refuses_what_the_loader_refuses(
    tmp_path: Path, document: dict[str, object]
) -> None:
    path = _write(tmp_path, yaml.safe_dump(document))

    assert not Draft202012Validator(_schema()).is_valid(document)
    with pytest.raises(ProfileError):
        load_profile(path)


def _as_written(profile: Profile) -> dict[str, object]:
    """Write a preset as a `guardana.yaml` would state it, every value it sets spelled out."""
    fail_on = profile.policy.fail_on
    privacy = profile.privacy
    written: dict[str, object] = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "name": profile.name,
        "rules": {"include": list(profile.policy.include), "exclude": list(profile.policy.exclude)},
        "fail_on": {
            "severity": fail_on.severity.name.lower(),
            "min_confidence": fail_on.min_confidence,
            "fail_on_inconclusive": fail_on.fail_on_inconclusive,
            "fail_on_error": fail_on.fail_on_error,
            "fail_on_skipped": fail_on.fail_on_skipped,
        },
        "privacy": {
            "evidence_mode": str(privacy.mode),
            "redact_emails": privacy.redact_emails,
            "redact_ip_addresses": privacy.redact_ip_addresses,
            "hash_identifiers": privacy.hash_identifiers,
            "custom_patterns": list(privacy.custom_patterns),
            "max_evidence_bytes": privacy.max_evidence_bytes,
            "keep_exchanges": privacy.keep_exchanges,
        },
        "trials": profile.trials,
        "delivery": {"required": profile.delivery_required},
    }
    return written


def _documents() -> list[tuple[str, dict[str, object] | None, Path | None]]:
    stored = sorted([*_HISTORICAL.glob("*.yaml"), *_HISTORICAL.glob("*.yml")])
    return [
        *((f"preset-{name}", _as_written(preset(name)), None) for name in PRESET_NAMES),
        ("init", None, None),
        *((f"historical-{path.stem}", None, path) for path in stored),
    ]


def _init_template(tmp_path: Path) -> Path:
    from guardana.cli.init import init  # noqa: PLC0415 — the template `guardana init` writes

    path = tmp_path / "guardana.yaml"
    init(path)
    return path


@pytest.mark.parametrize(
    ("label", "written", "stored"), _documents(), ids=[d[0] for d in _documents()]
)
def test_every_profile_guardana_writes_or_wrote_satisfies_the_schema(
    tmp_path: Path, label: str, written: dict[str, object] | None, stored: Path | None
) -> None:
    if written is not None:
        path = _write(tmp_path, yaml.safe_dump(written))
    elif stored is not None:
        path = stored
    else:
        path = _init_template(tmp_path)

    Draft202012Validator(_schema()).validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    loaded = load_profile(path)
    if label.startswith("preset-"):
        assert profile_digest(loaded) == profile_digest(preset(label.removeprefix("preset-")))
