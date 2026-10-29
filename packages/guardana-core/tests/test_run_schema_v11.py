"""Run schema 11 records the digest of the document a run read, and carries a v10 run forward.

One new fact: `target.document`, the SHA-256 of the bytes read and whether they were the
whole document. A version-10 run arrives with it null, which says no digest was recorded,
never that the document matched anything.
"""

import copy
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _documents import run_manifest, saved_run_at_v10, saved_run_at_v11, scan_result
from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v10
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report.load import load_report
from guardana.core.report.serialize import run_to_dict
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_DIGEST = "sha256:" + "ab" * 32


def _errors(document: dict[str, Any], version: int = 11) -> list[str]:
    """Validate `document` against the schema at `version`, in the shape that version wrote."""
    if version == 11:
        document = saved_run_at_v11(document)
    schema = json.loads((_SCHEMAS / f"run-v{version}.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _target(document: dict[str, Any]) -> dict[str, Any]:
    target: dict[str, Any] = document["run"]["target"]
    return target


def _write(document: dict[str, Any], tmp_path: Path) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# The document this build writes


def test_the_written_document_satisfies_the_v11_schema() -> None:
    assert not _errors(_document())


def test_every_document_field_is_written() -> None:
    assert _target(_document())["document"] == {
        "digest": _DIGEST,
        "kind": "content_prefix",
        "bytes": 8192,
    }


@pytest.mark.parametrize(
    "document",
    [
        None,
        DocumentDigest(digest=_DIGEST, kind=DigestKind.CONTENT, bytes=0),
        DocumentDigest(digest=_DIGEST, kind=DigestKind.CONTENT_PREFIX, bytes=65_536),
    ],
    ids=["not recorded", "empty content", "prefix"],
)
def test_the_document_digest_survives_being_saved_and_read_back(
    document: DocumentDigest | None, tmp_path: Path
) -> None:
    manifest = replace(run_manifest(), target=replace(run_manifest().target, document=document))
    saved = run_to_dict(scan_result(), manifest)

    assert not _errors(saved)
    assert manifest_from_dict(manifest_to_dict(manifest)) == manifest
    assert load_report(_write(saved, tmp_path)).manifest.target.document == document


def test_not_recorded_is_written_as_null_rather_than_left_out() -> None:
    manifest = replace(run_manifest(), target=replace(run_manifest().target, document=None))

    assert manifest_to_dict(manifest)["target"]["document"] is None  # type: ignore[index]


# The loader and the schema refuse what no reader of a document produces


def _set(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    def apply(target: dict[str, Any]) -> None:
        target["document"][key] = value

    return apply


def _drop(key: str) -> Callable[[dict[str, Any]], None]:
    def apply(target: dict[str, Any]) -> None:
        del target["document"][key]

    return apply


_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "document missing": lambda target: target.pop("document"),
    "not an object": lambda target: target.update(document=_DIGEST),
    "unknown key": _set("algorithm", "sha256"),
    "digest missing": _drop("digest"),
    "digest bare hex": _set("digest", "ab" * 32),
    "digest another algorithm": _set("digest", "md5:" + "ab" * 16),
    "kind missing": _drop("kind"),
    "kind unknown": _set("kind", "name_and_size"),
    "kind null": _set("kind", None),
    "bytes missing": _drop("bytes"),
    "bytes negative": _set("bytes", -1),
    "bytes a string": _set("bytes", "8192"),
    "bytes a flag": _set("bytes", True),
}


@pytest.mark.parametrize("breakage", _BREAKAGES)
def test_the_loader_and_the_v11_schema_refuse_the_same_malformed_document(breakage: str) -> None:
    document = _document()
    _BREAKAGES[breakage](_target(document))

    with pytest.raises(ManifestLoadError, match=r"run\.target"):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v11 schema accepts {breakage}, which the loader refuses"


def test_a_saved_run_with_an_unknown_kind_is_refused_on_load(tmp_path: Path) -> None:
    from guardana.core.report.load import ReportLoadError  # noqa: PLC0415

    document = _document()
    _target(document)["document"]["kind"] = "name_and_size"

    with pytest.raises(ReportLoadError, match="kind"):
        load_report(_write(document, tmp_path))


# Version 10 forward


def test_a_v10_run_migrates_to_11_with_the_document_not_recorded() -> None:
    v10 = saved_run_at_v10(_document())
    assert not _errors(v10, 10), "the fixture must be a real version-10 document"

    migrated = migrate_v10(v10)

    assert migrated["schema_version"] == 11
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v11.schema.json"
    assert not _errors(migrated)
    assert _target(migrated)["document"] is None
    assert _target(migrated)["fingerprint"] == _target(v10)["fingerprint"]


def test_the_migration_overwrites_a_document_digest_a_v10_run_should_not_hold() -> None:
    # No version-10 build recorded a document digest, so one found there was not written by one.
    v10 = saved_run_at_v10(_document())
    _target(v10)["document"] = _target(_document())["document"]

    assert _target(migrate_v10(v10))["document"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v10 = saved_run_at_v10(_document())
    before = copy.deepcopy(v10)

    migrated = migrate_v10(v10)

    assert v10 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v10(migrated) == v10


def test_a_loaded_v10_run_says_it_was_migrated_and_records_no_document(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v10(_document()), tmp_path))

    assert report.manifest.migrated_from == 10
    assert report.manifest.target.document is None
