"""Run schema 10 records what the configured judges spent, and carries a v9 run forward.

One new fact: `usage.judge`, each `evaluators:` block's own meter — requests, tokens and
whether its ceiling stopped the run — kept apart from the target's counts. A version-9
run arrives with it null, which says nobody counted judge calls, never that none were made.
"""

import copy
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _documents import run_manifest, saved_run_at_v9, saved_run_at_v10, scan_result
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v9
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.manifest.usage import JudgeUsage, RunUsage
from guardana.core.report.load import load_report
from guardana.core.report.serialize import run_to_dict
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _errors(document: dict[str, Any], version: int = 10) -> list[str]:
    """Validate `document` against the schema at `version`, in the shape that version wrote."""
    if version == 10:
        document = saved_run_at_v10(document)
    schema = json.loads((_SCHEMAS / f"run-v{version}.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _judge(document: dict[str, Any]) -> dict[str, Any]:
    judge: dict[str, Any] = document["run"]["usage"]["judge"]
    return judge


def _write(document: dict[str, Any], tmp_path: Path) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# The document this build writes


def test_the_written_document_satisfies_the_v10_schema() -> None:
    assert not _errors(_document())


def test_every_judge_field_is_written() -> None:
    assert _judge(_document()) == {
        "llm_judge": {
            "requests": 30,
            "input_tokens": 9000,
            "output_tokens": 600,
            "requests_missing_token_counts": 2,
            "budget_exhausted": True,
        },
        "guard": {
            "requests": 12,
            "input_tokens": None,
            "output_tokens": None,
            "requests_missing_token_counts": 12,
            "budget_exhausted": False,
        },
    }


@pytest.mark.parametrize(
    "judge",
    [
        None,
        {"llm_judge": JudgeUsage()},
        {"guard": JudgeUsage(requests=3, input_tokens=90, output_tokens=3)},
    ],
    ids=["nobody counted", "counted zero", "guard only"],
)
def test_judge_usage_survives_being_saved_and_read_back(
    judge: dict[str, JudgeUsage] | None, tmp_path: Path
) -> None:
    manifest = replace(run_manifest(), usage=replace(run_manifest().usage, judge=judge))
    document = run_to_dict(scan_result(), manifest)

    assert not _errors(document)
    assert manifest_from_dict(manifest_to_dict(manifest)) == manifest
    assert load_report(_write(document, tmp_path)).manifest.usage.judge == judge


def test_counted_zero_and_nobody_counted_are_different_documents() -> None:
    counted = manifest_to_dict(
        replace(run_manifest(), usage=RunUsage(judge={"llm_judge": JudgeUsage()}))
    )
    uncounted = manifest_to_dict(replace(run_manifest(), usage=RunUsage()))

    assert counted["usage"]["judge"] == {  # type: ignore[index]
        "llm_judge": {
            "requests": 0,
            "input_tokens": None,
            "output_tokens": None,
            "requests_missing_token_counts": 0,
            "budget_exhausted": False,
        }
    }
    assert uncounted["usage"]["judge"] is None  # type: ignore[index]


# The model and the loader refuse what no meter produces


@pytest.mark.parametrize(
    ("judge", "match"),
    [({}, "empty map"), ({"target": JudgeUsage()}, "no judge meters")],
)
def test_the_model_refuses_judge_usage_no_meter_writes(
    judge: dict[str, JudgeUsage], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        RunUsage(judge=judge)


def test_the_model_refuses_a_negative_count() -> None:
    with pytest.raises(ValueError, match="negative"):
        JudgeUsage(requests=-1)


def _set(where: str, key: str, value: object) -> Callable[[dict[str, Any]], None]:
    def apply(usage: dict[str, Any]) -> None:
        block = usage if where == "usage" else usage["judge"][where]
        block[key] = value

    return apply


def _drop(where: str, key: str) -> Callable[[dict[str, Any]], None]:
    def apply(usage: dict[str, Any]) -> None:
        block = usage if where == "usage" else usage["judge"][where]
        del block[key]

    return apply


def _add_block(usage: dict[str, Any]) -> None:
    usage["judge"]["reference_judge"] = usage["judge"]["llm_judge"]


_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "judge missing": _drop("usage", "judge"),
    "empty": _set("usage", "judge", {}),
    "unknown block": _add_block,
    "entry not an object": lambda usage: usage["judge"].update(guard=12),
    "requests missing": _drop("guard", "requests"),
    "requests null": _set("guard", "requests", None),
    "tokens missing": _drop("guard", "input_tokens"),
    "tokens a string": _set("llm_judge", "input_tokens", "9000"),
    "negative": _set("llm_judge", "requests", -1),
    "stop missing": _drop("llm_judge", "budget_exhausted"),
    "stop not a flag": _set("llm_judge", "budget_exhausted", "yes"),
}


def _broken(breakage: str) -> dict[str, Any]:
    document = _document()
    _BREAKAGES[breakage](document["run"]["usage"])
    return document


@pytest.mark.parametrize("breakage", _BREAKAGES)
def test_the_loader_and_the_v10_schema_refuse_the_same_malformed_judge_block(
    breakage: str,
) -> None:
    document = _broken(breakage)

    with pytest.raises(ManifestLoadError, match=r"usage"):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v10 schema accepts {breakage}, which the loader refuses"


def test_the_v10_schema_refuses_an_unknown_key_in_a_judge_entry() -> None:
    document = _document()
    _set("llm_judge", "cost", 1.5)(document["run"]["usage"])

    assert _errors(document)


# Version 9 forward


def test_a_v9_run_migrates_to_10_with_judge_usage_unknown() -> None:
    v9 = saved_run_at_v9(_document())
    assert not _errors(v9, 9), "the fixture must be a real version-9 document"

    migrated = migrate_v9(v9)

    assert migrated["schema_version"] == 10
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v10.schema.json"
    assert not _errors(migrated)
    assert migrated["run"]["usage"]["judge"] is None
    assert migrated["run"]["usage"]["requests"] == 42, "the target's bill is carried as it was"


def test_a_v9_run_reads_back_with_judge_usage_unknown_never_zero(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v9(_document()), tmp_path))

    assert report.manifest.usage.judge is None
    assert report.manifest.usage.requests == 42


def test_the_migration_overwrites_judge_usage_a_v9_document_should_not_hold() -> None:
    # No version-9 build counted judge calls, so a count found there was not written by one.
    v9 = saved_run_at_v9(_document())
    v9["run"]["usage"]["judge"] = _judge(_document())

    assert migrate_v9(v9)["run"]["usage"]["judge"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v9 = saved_run_at_v9(_document())
    before = copy.deepcopy(v9)

    migrated = migrate_v9(v9)

    assert v9 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v9(migrated) == v9


def test_a_loaded_v9_run_says_it_was_migrated_so_its_unknowns_are_not_read_as_zero(
    tmp_path: Path,
) -> None:
    report = load_report(_write(saved_run_at_v9(_document()), tmp_path))

    assert report.manifest.migrated_from == 9
    assert report.manifest.usage.judge is None
