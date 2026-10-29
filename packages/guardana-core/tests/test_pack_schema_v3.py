"""Schema 3: a pack declares installed outputs, and a lock pins them only when there are any.

A manifest naming a renderer or reporter needs an `output_api`, and a schema 2 manifest
naming one is refused, because a build that predates outputs reads the same file and
drops them silently. A lock stays schema 2 until an output is pinned or unlocked, so a
team with no outputs keeps a lock every earlier build reads.
"""

import json
import shutil
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from _fake_distribution import MARKING_MODULE, FakeSite
from guardana.core.entrypoints import RENDERER_GROUP
from guardana.core.pack import (
    MANIFEST_NAME,
    PACK_SCHEMA_VERSION,
    PackError,
    check_pack,
    discover_packs,
    load_manifest,
)
from guardana.core.pack.discover import Registered
from guardana.core.pack.lock import (
    LOCK_SCHEMA_VERSION,
    DriftKind,
    Installed,
    compare,
    lock_from_dict,
    lock_of,
    lock_to_dict,
)
from guardana.core.pack.model import ApiRange, PackManifest
from guardana.core.plugins import PluginMode, PluginTrust
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_DIST = "acme-guardana-outputs"

_OUTPUTS = """\
schema_version: 3
name: acme-outputs
extension_api: ">=2,<3"
output_api: ">=1,<2"
provides:
  renderers: [acme-table]
  reporters: [acme-webhook]
"""

_V2_OUTPUT_API_ONLY = """\
schema_version: 2
name: a
extension_api: ">=2,<3"
output_api: ">=1,<2"
provides:
  rules: [acme.rule]
"""

_V1_OUTPUT_API_ONLY = """\
schema_version: 1
name: a
extension_api: ">=1,<2"
output_api: ">=1,<2"
provides:
  rules: [acme.rule]
"""


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((_SCHEMAS / name).read_text(encoding="utf-8")))


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / MANIFEST_NAME
    path.write_text(body, encoding="utf-8")
    return path


def _manifest() -> PackManifest:
    return PackManifest(
        name="acme-outputs",
        extension_api=ApiRange(2, 3),
        source=MANIFEST_NAME,
        renderers=("acme-table",),
        reporters=("acme-webhook",),
        output_api=ApiRange(1, 2),
    )


# --- the manifest ---------------------------------------------------------------


def test_a_schema_3_manifest_declares_its_outputs_and_their_api(tmp_path: Path) -> None:
    manifest = load_manifest(_write(tmp_path, _OUTPUTS))

    assert manifest.renderers == ("acme-table",)
    assert manifest.reporters == ("acme-webhook",)
    assert manifest.output_api == ApiRange(1, 2)
    assert manifest.schema_version == PACK_SCHEMA_VERSION == 3
    assert manifest.migrated_from is None
    assert manifest.provides == ("renderer:acme-table", "reporter:acme-webhook")


def test_the_design_manifest_satisfies_the_published_schema() -> None:
    validator = _validator("pack-manifest-v3.schema.json")

    assert not list(validator.iter_errors(yaml.safe_load(_OUTPUTS)))


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.pop("output_api"),
        lambda d: d["provides"].update(renderers=["json"]),
        lambda d: d["provides"].update(reporters=["https"]),
        lambda d: d["provides"].update(renderers=["Acme_Table"]),
        lambda d: d.update(provides={"rules": ["acme.rule"]}),
    ],
    ids=["no-output-api", "reserved-renderer", "reserved-reporter", "invalid-name", "extra-api"],
)
def test_the_published_schema_refuses_what_the_loader_refuses(
    tmp_path: Path, change: Callable[[dict[str, Any]], object]
) -> None:
    document: dict[str, Any] = yaml.safe_load(_OUTPUTS)
    change(document)

    assert list(_validator("pack-manifest-v3.schema.json").iter_errors(document))
    with pytest.raises(PackError):
        load_manifest(_write(tmp_path, yaml.safe_dump(document)))


@pytest.mark.parametrize(
    "body",
    [
        _OUTPUTS.replace("schema_version: 3", "schema_version: 2"),
        _OUTPUTS.replace("schema_version: 3", "schema_version: 2")
        .replace('output_api: ">=1,<2"\n', "")
        .replace("  renderers: [acme-table]\n", ""),
        _V2_OUTPUT_API_ONLY,
        _OUTPUTS.replace("schema_version: 3", "schema_version: 1"),
        _V1_OUTPUT_API_ONLY,
    ],
    ids=["v2-renderers", "v2-reporters", "v2-output-api", "v1-outputs", "v1-output-api"],
)
def test_an_older_manifest_naming_an_output_key_is_refused(tmp_path: Path, body: str) -> None:
    """A key invented after the version a document claims would be dropped by an older build."""
    with pytest.raises(PackError, match=r"unknown schema [12]"):
        load_manifest(_write(tmp_path, body))


def test_a_schema_2_manifest_without_outputs_is_current_not_migrated(tmp_path: Path) -> None:
    body = 'schema_version: 2\nname: a\nextension_api: ">=2,<3"\nprovides:\n  rules: [acme.rule]\n'

    manifest = load_manifest(_write(tmp_path, body))

    assert manifest.schema_version == 2
    assert manifest.migrated_from is None
    assert manifest.output_api is None
    assert manifest.renderers == manifest.reporters == ()


def test_an_output_without_an_output_api_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PackError, match="'output_api' is required"):
        load_manifest(_write(tmp_path, _OUTPUTS.replace('output_api: ">=1,<2"\n', "")))


def test_an_output_api_without_an_output_is_refused(tmp_path: Path) -> None:
    body = (
        'schema_version: 3\nname: a\nextension_api: ">=2,<3"\noutput_api: ">=1,<2"\n'
        "provides:\n  rules: [acme.rule]\n"
    )

    with pytest.raises(PackError, match="names no renderer or reporter"):
        load_manifest(_write(tmp_path, body))


@pytest.mark.parametrize("value", ['">=1"', '"1"', '">=2,<1"', "1"])
def test_an_output_api_that_is_not_a_closed_range_is_refused(tmp_path: Path, value: str) -> None:
    with pytest.raises(PackError, match="'output_api'"):
        load_manifest(_write(tmp_path, _OUTPUTS.replace('">=1,<2"', value)))


@pytest.mark.parametrize(
    ("key", "name"),
    [
        ("renderers", "Acme-Table"),
        ("renderers", "acme_table"),
        ("renderers", "1acme"),
        ("reporters", "a" * 41),
    ],
)
def test_an_output_name_that_could_never_be_selected_is_refused(
    tmp_path: Path, key: str, name: str
) -> None:
    body = _OUTPUTS.replace("[acme-table]" if key == "renderers" else "[acme-webhook]", f"[{name}]")

    with pytest.raises(PackError, match="not an output name"):
        load_manifest(_write(tmp_path, body))


@pytest.mark.parametrize(
    ("key", "name"),
    [
        ("renderers", "sarif"),
        ("renderers", "guardana-table"),
        ("reporters", "server"),
        ("reporters", "guardana"),
    ],
)
def test_a_reserved_output_name_is_refused(tmp_path: Path, key: str, name: str) -> None:
    body = _OUTPUTS.replace("[acme-table]" if key == "renderers" else "[acme-webhook]", f"[{name}]")

    with pytest.raises(PackError, match="reserved"):
        load_manifest(_write(tmp_path, body))


def test_a_name_reserved_for_the_other_kind_is_allowed(tmp_path: Path) -> None:
    """`server` is a reporter form, not a format, so a format may take the name."""
    manifest = load_manifest(_write(tmp_path, _OUTPUTS.replace("[acme-table]", "[server]")))

    assert manifest.renderers == ("server",)


# --- what check_pack says about outputs -----------------------------------------


def _registered() -> Registered:
    return Registered(renderers={"acme-table": _DIST}, reporters={"acme-webhook": _DIST})


def test_a_pack_whose_outputs_are_installed_from_its_own_distribution_is_accurate() -> None:
    assert check_pack(_manifest(), _registered(), _DIST).problems == ()


@pytest.mark.parametrize(
    ("output_api", "words"),
    [
        (ApiRange(2, 3), "needs output API >=2 and this build implements 1 — the pack is newer"),
        (ApiRange(0, 1), "needs output API <1 and this build implements 1 — the pack is older"),
    ],
)
def test_an_output_api_this_build_does_not_implement_is_a_problem(
    output_api: ApiRange, words: str
) -> None:
    check = check_pack(replace(_manifest(), output_api=output_api), _registered(), _DIST)

    assert [problem for problem in check.problems if words in problem], check.problems


def test_an_output_declared_without_an_output_api_is_a_problem() -> None:
    check = check_pack(replace(_manifest(), output_api=None), _registered(), _DIST)

    assert not check.ok
    assert "no output_api" in check.problems[0]


def test_an_output_declared_and_not_installed_is_a_problem() -> None:
    check = check_pack(_manifest(), replace(_registered(), reporters={}), _DIST)

    assert check.problems == (
        "declares reporter acme-webhook and does not register it — a team reading this "
        "manifest believes a check runs that does not",
    )


def test_an_output_another_distribution_installs_is_a_problem() -> None:
    check = check_pack(
        _manifest(), replace(_registered(), renderers={"acme-table": "acme-fork"}), _DIST
    )

    assert len(check.problems) == 1
    assert "renderer acme-table (registered by acme-fork)" in check.problems[0]


def test_an_output_several_distributions_install_is_refused_by_name() -> None:
    registered = replace(
        _registered(), renderers={}, output_collisions={"renderer:acme-table": ("a", "b")}
    )

    check = check_pack(_manifest(), registered, _DIST)

    assert check.problems == (
        "declares renderer acme-table, which 2 distributions provide (a, b) — selecting it "
        "is refused",
    )


def test_a_collision_under_the_other_kind_does_not_touch_this_output() -> None:
    registered = replace(_registered(), output_collisions={"reporter:acme-table": ("a", "b")})

    assert check_pack(_manifest(), registered, _DIST).ok


# --- the lock -------------------------------------------------------------------


_RULE = "acme.agent.customer_data"


def _rules_only() -> PackManifest:
    return PackManifest("acme-rules", ApiRange(2, 3), MANIFEST_NAME, rules=(_RULE,))


def _installed() -> Installed:
    return Installed(
        rules={_RULE: "1111222233334444"},
        renderers={"acme-table": _DIST},
        reporters={"acme-webhook": _DIST},
    )


def _packs() -> list[tuple[str, str, PackManifest]]:
    """Two packs, in the name order a lock is written in, so a read-back compares equal."""
    return [(_DIST, "0.1.0", _manifest()), ("acme-rules", "1.0", _rules_only())]


def test_a_lock_with_no_output_is_written_exactly_as_schema_2() -> None:
    """Byte for byte what this build wrote before outputs, so every earlier build reads it."""
    lock = lock_of(
        [("acme-rules", "1.0", _rules_only())], replace(_installed(), renderers={}, reporters={})
    )

    written = yaml.safe_dump(lock_to_dict(lock), sort_keys=False)

    assert written == (
        "schema_version: 2\n"
        "extension_api: 2\n"
        "packs:\n"
        "- name: acme-rules\n"
        "  distribution: acme-rules\n"
        "  version: '1.0'\n"
        "  rules:\n"
        "    acme.agent.customer_data:\n"
        "      digest: '1111222233334444'\n"
        "  evaluators: []\n"
        "  targets: []\n"
        "  taxonomies: {}\n"
        "unlocked: []\n"
    )


def test_a_lock_pinning_an_output_is_schema_3_and_satisfies_the_published_schema() -> None:
    document = lock_to_dict(lock_of(_packs(), _installed()))

    assert document["schema_version"] == LOCK_SCHEMA_VERSION == 3
    assert not list(_validator("pack-lock-v3.schema.json").iter_errors(document))
    by_name = {pack["name"]: pack for pack in document["packs"]}
    assert by_name["acme-outputs"]["renderers"] == ["acme-table"]
    assert by_name["acme-outputs"]["reporters"] == ["acme-webhook"]
    assert by_name["acme-rules"]["renderers"] == by_name["acme-rules"]["reporters"] == []
    assert list(by_name["acme-outputs"]).index("renderers") == (
        list(by_name["acme-outputs"]).index("targets") + 1
    )


def test_a_schema_3_lock_reads_back_as_the_lock_that_was_written() -> None:
    lock = lock_of(_packs(), _installed())

    restored = lock_from_dict(lock_to_dict(lock), "guardana-lock.yaml")

    assert restored == lock
    assert restored.schema_version == 3
    assert restored.migrated_from is None


def test_an_unlocked_output_alone_makes_the_lock_schema_3() -> None:
    lock = lock_of([("acme-rules", "1.0", _rules_only())], replace(_installed(), reporters={}))

    document = lock_to_dict(lock)

    assert lock.unlocked == ("renderer:acme-table",)
    assert document["schema_version"] == 3
    assert not list(_validator("pack-lock-v3.schema.json").iter_errors(document))


@pytest.mark.parametrize("key", ["renderers", "reporters"])
def test_a_schema_3_lock_missing_an_output_list_is_refused(key: str) -> None:
    document = lock_to_dict(lock_of(_packs(), _installed()))
    del document["packs"][0][key]

    assert list(_validator("pack-lock-v3.schema.json").iter_errors(document))
    with pytest.raises(PackError, match=key):
        lock_from_dict(document, "guardana-lock.yaml")


def _older(schema: int) -> dict[str, Any]:
    document = lock_to_dict(lock_of(_packs(), _installed()))
    document["schema_version"] = schema
    if schema == 1:
        for pack in document["packs"]:
            for group in ("rules", "taxonomies"):
                pack[group] = {name: entry["digest"] for name, entry in pack[group].items()}
    return document


@pytest.mark.parametrize("schema", [1, 2])
@pytest.mark.parametrize("key", ["renderers", "reporters"])
def test_an_older_lock_carrying_an_output_key_is_refused(schema: int, key: str) -> None:
    """Ignoring the key would pin nothing while the file looks as if it pinned the output."""
    document = _older(schema)
    for pack in document["packs"]:
        pack.pop("renderers" if key == "reporters" else "reporters")

    with pytest.raises(PackError, match=rf"schema {schema} has no 'renderers' or 'reporters'"):
        lock_from_dict(document, "guardana-lock.yaml")


@pytest.mark.parametrize("schema", [1, 2])
def test_an_older_lock_listing_an_unlocked_output_is_refused(schema: int) -> None:
    document = _older(schema)
    for pack in document["packs"]:
        del pack["renderers"], pack["reporters"]
    document["unlocked"] = ["reporter:acme-webhook"]

    with pytest.raises(PackError, match="cannot list an output"):
        lock_from_dict(document, "guardana-lock.yaml")


def test_a_schema_2_lock_read_with_an_output_installed_reports_it_added() -> None:
    before = lock_of(
        [
            (
                _DIST,
                "0.1.0",
                replace(_manifest(), renderers=(), reporters=(), output_api=None, rules=(_RULE,)),
            )
        ],
        replace(_installed(), renderers={}, reporters={}),
    )
    document = lock_to_dict(before)
    assert document["schema_version"] == 2
    locked = lock_from_dict(document, "guardana-lock.yaml")

    now = lock_of([(_DIST, "0.1.0", replace(_manifest(), rules=(_RULE,)))], _installed())
    drift = compare(locked, now)

    assert {(entry.kind, entry.subject) for entry in drift} == {
        (DriftKind.ADDED, "acme-table"),
        (DriftKind.ADDED, "acme-webhook"),
    }
    assert {entry.detail for entry in drift} == {
        "renderer is installed and was never locked",
        "reporter is installed and was never locked",
    }


def test_an_output_no_longer_provided_is_reported_removed() -> None:
    locked = lock_of(_packs(), _installed())
    now = lock_of(
        [
            ("acme-rules", "1.0", _rules_only()),
            (_DIST, "0.1.0", replace(_manifest(), reporters=())),
        ],
        replace(_installed(), reporters={}),
    )

    drift = compare(locked, now)

    assert [(entry.kind, entry.subject) for entry in drift] == [(DriftKind.REMOVED, "acme-webhook")]
    assert drift[0].detail == "reporter was locked and is gone"


@pytest.mark.parametrize("kind", ["renderer", "reporter"])
def test_an_output_declared_and_not_installed_refuses_the_lock(kind: str) -> None:
    if kind == "renderer":
        installed = replace(_installed(), renderers={})
    else:
        installed = replace(_installed(), reporters={})

    with pytest.raises(PackError, match=rf"acme-outputs declares {kind} acme-"):
        lock_of(_packs(), installed)


def test_an_output_another_distribution_registers_is_not_pinned_for_the_pack() -> None:
    locked = lock_of(_packs(), _installed())
    foreign = replace(_installed(), renderers={"acme-table": "acme-imposter"})

    now = lock_of(_packs(), foreign)

    (pack,) = [p for p in now.packs if p.name == "acme-outputs"]
    assert pack.renderers == ()
    assert pack.reporters == ("acme-webhook",)
    assert now.unlocked == ("renderer:acme-table",)
    assert (DriftKind.REMOVED, "acme-table") in {(d.kind, d.subject) for d in compare(locked, now)}


def test_writing_a_lock_with_an_output_another_distribution_registers_is_refused() -> None:
    foreign = replace(_installed(), reporters={"acme-webhook": None})

    said = "acme-outputs declares reporter acme-webhook, which an unnamed distribution registers"
    with pytest.raises(PackError, match=said):
        lock_of(_packs(), foreign, writing=True)


def test_installed_ids_spell_outputs_by_kind() -> None:
    assert _installed().ids() == {_RULE, "renderer:acme-table", "reporter:acme-webhook"}


# --- discovery ------------------------------------------------------------------


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def test_a_pack_that_ships_only_an_output_is_discovered(site: FakeSite, tmp_path: Path) -> None:
    """The output groups are walked, so an output-only pack's manifest is read at all."""
    module = site.module(MARKING_MODULE, package=True)
    shutil.copyfile(_write(tmp_path, _OUTPUTS), site.root / module.name / MANIFEST_NAME)
    site.distribution(_DIST, (RENDERER_GROUP, "acme-table", module.name))

    admitted = discover_packs(PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({_DIST})))
    refused = discover_packs(PluginTrust(mode=PluginMode.BUILTINS))

    assert [(d, m.name) for d, _, m in admitted.packs if d == _DIST] == [(_DIST, "acme-outputs")]
    assert [ep.module for ep in refused.refused] == [module.name]
