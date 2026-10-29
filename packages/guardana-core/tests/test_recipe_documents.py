"""The recipe a team writes and the lock Guardana writes, walked key by key.

A recipe key whose deletion changes nothing is a setting the team believes took effect
and did not; a lock key whose deletion changes nothing is a pin that holds nothing. Both
are found the same way: delete each key in turn and expect a refusal or a different
reading. The published schemas are held to the same documents.
"""

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import yaml
from _roundtrip import Document, key_paths, render, unread_keys, without
from guardana.core.recipe import (
    _CONNECTION_KEYS,
    _DEPLOYMENT_KEYS,
    _OUTPUT_KEYS,
    _SUBJECT_KEYS,
    _TARGET_KEYS,
    _TOP_KEYS,
    RECIPE_LOCK_SCHEMA_VERSION,
    RECIPE_SCHEMA_VERSION,
    PinnedEvaluator,
    PinnedOrigin,
    PinnedRule,
    PinnedTarget,
    RecipeError,
    RecipeLock,
    load_recipe,
    lock_to_dict,
    read_lock,
)
from guardana.core.recipe_source import SourcePin
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_DIGEST = "sha256:" + "ab" * 32


def _validator(name: str) -> Draft202012Validator:
    schema: dict[str, Any] = json.loads((_SCHEMAS / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _recipe() -> dict[str, Any]:
    """A recipe with every key the loader accepts, each away from its default."""
    return {
        "schema_version": RECIPE_SCHEMA_VERSION,
        "name": "support-bot",
        "profile": "guardana.yaml",
        "subject": {
            "kind": "model_harness",
            "fixtures": "guardana-fixtures.yaml",
            "connection": {
                "url": "http://127.0.0.1:8080",
                "model": "support-bot",
                "provider": "ollama",
                "api_key_env": "SUPPORT_BOT_KEY",
                "adapter": "adapter.yaml",
                "system_prompt_file": "prompt.txt",
            },
        },
        "deployment": {"ai_system": "support-bot", "environment": "ci", "deployment_id": "42"},
        "output": {"directory": "artifact", "exchanges": True},
    }


def test_the_recipe_fixture_carries_every_key_the_loader_accepts() -> None:
    document = _recipe()
    subject = document["subject"]

    missing = (
        sorted(_TOP_KEYS - set(document))
        + sorted(f"subject.{k}" for k in _SUBJECT_KEYS - set(subject) - {"recording", "target"})
        + sorted(f"target.{k}" for k in _TARGET_KEYS - set(_target_recipe()["subject"]["target"]))
        + sorted(f"connection.{k}" for k in _CONNECTION_KEYS - set(subject["connection"]))
        + sorted(f"deployment.{k}" for k in _DEPLOYMENT_KEYS - set(document["deployment"]))
        + sorted(f"output.{k}" for k in _OUTPUT_KEYS - set(document["output"]))
    )

    assert not missing, f"recipe keys the loader accepts and this fixture never uses: {missing}"


def test_no_key_of_a_recipe_can_be_deleted_without_the_loader_noticing(tmp_path: Path) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "guardana-recipe.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        recipe = load_recipe(path)
        return tuple(
            getattr(recipe, f.name) for f in fields(recipe) if f.name not in {"path", "digest"}
        )

    ignored = unread_keys(_recipe(), read, root="recipe", refusal=RecipeError)

    assert not ignored, "recipe keys that change nothing when deleted:\n  " + "\n  ".join(ignored)


def _target_recipe() -> dict[str, Any]:
    """A recipe whose subject is an installed target, every target key away from its default."""
    document = _recipe()
    document["subject"] = {
        "kind": "application",
        "target": {"locator": "acme-chat://support", "options": {"region": "eu", "tier": ""}},
    }
    return document


def test_no_key_of_a_target_recipe_can_be_deleted_without_the_loader_noticing(
    tmp_path: Path,
) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "guardana-recipe.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        recipe = load_recipe(path)
        return tuple(
            getattr(recipe, f.name) for f in fields(recipe) if f.name not in {"path", "digest"}
        )

    ignored = unread_keys(_target_recipe(), read, root="recipe", refusal=RecipeError)

    assert not ignored, "recipe keys that change nothing when deleted:\n  " + "\n  ".join(ignored)


def _schema_2(document: dict[str, Any]) -> dict[str, Any]:
    """The same recipe as a schema-2 build wrote it: no target."""
    return {**document, "schema_version": 2}


def _schema_1(document: dict[str, Any]) -> dict[str, Any]:
    """The same recipe as a schema-1 build wrote it: no fixtures."""
    subject = {k: v for k, v in document["subject"].items() if k != "fixtures"}
    return {**document, "schema_version": 1, "subject": subject}


def test_a_recording_recipe_is_read_and_its_schema_accepts_both_subjects(tmp_path: Path) -> None:
    recording = _recipe()
    recording["subject"] = {"kind": "application", "recording": "answers.jsonl"}
    path = tmp_path / "guardana-recipe.yaml"
    path.write_text(yaml.safe_dump(recording), encoding="utf-8")

    assert load_recipe(path).recording == tmp_path / "answers.jsonl"
    v1, v2, v3 = (_validator(f"recipe-v{n}.schema.json") for n in (1, 2, 3))
    assert list(v3.iter_errors(recording)) == []
    assert list(v3.iter_errors(_recipe())) == []
    assert list(v3.iter_errors(_target_recipe())) == []
    assert list(v2.iter_errors(_schema_2(recording))) == []
    assert list(v2.iter_errors(_schema_2(_recipe()))) == []
    assert list(v1.iter_errors(_schema_1(recording))) == []
    assert list(v1.iter_errors(_schema_1(_recipe()))) == []


def test_the_v3_schema_refuses_what_the_loader_refuses_beside_a_target() -> None:
    validator = _validator("recipe-v3.schema.json")
    with_fixtures = _target_recipe()
    with_fixtures["subject"]["fixtures"] = "guardana-fixtures.yaml"
    with_connection = _target_recipe()
    with_connection["subject"]["connection"] = _recipe()["subject"]["connection"]
    unkinded = _target_recipe()
    del unkinded["subject"]["kind"]
    numeric = _target_recipe()
    numeric["subject"]["target"]["options"]["region"] = 3

    for document in (with_fixtures, with_connection, unkinded, numeric):
        assert list(validator.iter_errors(document)), document["subject"]
    assert list(_validator("recipe-v2.schema.json").iter_errors(_schema_2(_target_recipe())))


def test_a_schema_1_recipe_is_read_as_one_without_fixtures(tmp_path: Path) -> None:
    path = tmp_path / "guardana-recipe.yaml"
    path.write_text(yaml.safe_dump(_schema_1(_recipe())), encoding="utf-8")

    assert load_recipe(path).fixtures is None


def test_each_schema_refuses_what_its_version_cannot_hold() -> None:
    fixtures_and_recording = _recipe()
    fixtures_and_recording["subject"] = {
        "kind": "application",
        "recording": "answers.jsonl",
        "fixtures": "guardana-fixtures.yaml",
    }

    assert list(_validator("recipe-v1.schema.json").iter_errors({**_recipe(), "schema_version": 1}))
    assert list(_validator("recipe-v2.schema.json").iter_errors(_schema_2(fixtures_and_recording)))
    assert list(_validator("recipe-v3.schema.json").iter_errors(fixtures_and_recording))
    assert list(_validator("recipe-v2.schema.json").iter_errors(_schema_1(_recipe())))


def test_the_schema_requires_a_kind_only_beside_a_connection(tmp_path: Path) -> None:
    validator = _validator("recipe-v3.schema.json")
    unkinded = _recipe()
    unkinded["subject"] = {"recording": "answers.jsonl"}
    path = tmp_path / "guardana-recipe.yaml"
    path.write_text(yaml.safe_dump(unkinded), encoding="utf-8")
    connected = _recipe()
    connected["subject"] = {
        key: value for key, value in connected["subject"].items() if key != "kind"
    }
    both = _recipe()
    both["subject"] = {**both["subject"], "recording": "answers.jsonl"}
    both["subject"].pop("kind")

    assert load_recipe(path).kind is None
    assert list(validator.iter_errors(unkinded)) == []
    assert list(validator.iter_errors(connected))
    assert list(validator.iter_errors(both))


def _lock() -> RecipeLock:
    """A lock with every field occupied, so no deletion can match a default by chance."""
    return RecipeLock(
        recipe=_DIGEST,
        guardana="0.36.0",
        trust="allowlist:acme-guardana-rules",
        profile=_DIGEST,
        rules={
            "acme.suite": PinnedRule(
                digest=_DIGEST, origin=PinnedOrigin("acme-guardana-rules", "1.2.0"), trials=3
            )
        },
        evaluators={
            "llm_judge": PinnedEvaluator(
                origin=PinnedOrigin("guardana-core", "0.36.0"),
                judge="model=judge-1; endpoint=sha256:00",
                calibration=_DIGEST,
            )
        },
        skipped={"acme.tools": "missing_capability"},
        subject_files={"adapter": _DIGEST},
        unpinned={"rule:acme.suite": "acme-guardana-rules: it holds more than 20000 files"},
        target=PinnedTarget("acme-chat", PinnedOrigin("acme-targets", "2.0")),
        sources={"acme-helpers": SourcePin(_DIGEST, 7)},
        schema_version=RECIPE_LOCK_SCHEMA_VERSION,
    )


def _v1_lock() -> dict[str, Any]:
    """A lock as a schema-1 build wrote it."""
    document = lock_to_dict(_lock())
    del document["target"], document["sources"]
    return {**document, "schema_version": 1, "unpinned": ["rule:acme.suite"]}


def test_a_lock_reads_back_as_written_and_validates_against_its_schema(tmp_path: Path) -> None:
    path = tmp_path / "guardana-recipe.lock.yaml"
    document = lock_to_dict(_lock())
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert read_lock(path) == _lock()
    assert list(_validator("recipe-lock-v2.schema.json").iter_errors(document)) == []
    assert list(_validator("recipe-lock-v1.schema.json").iter_errors(document))


def test_a_schema_1_lock_reads_back_as_written_and_still_meets_its_schema(tmp_path: Path) -> None:
    path = tmp_path / "guardana-recipe.lock.yaml"
    path.write_text(yaml.safe_dump(_v1_lock()), encoding="utf-8")

    read = read_lock(path)

    assert lock_to_dict(read) == _v1_lock()
    assert read.sources == {}
    assert read.target is None
    assert list(_validator("recipe-lock-v1.schema.json").iter_errors(_v1_lock())) == []
    assert list(_validator("recipe-lock-v2.schema.json").iter_errors(_v1_lock()))


def test_no_key_of_a_schema_1_lock_can_be_deleted_without_the_reader_noticing(
    tmp_path: Path,
) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "guardana-recipe.lock.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return read_lock(path)

    ignored = unread_keys(_v1_lock(), read, root="lock", refusal=RecipeError)

    assert not ignored, "lock keys that change nothing when deleted:\n  " + "\n  ".join(ignored)


def test_no_key_of_a_lock_can_be_deleted_without_the_reader_noticing(tmp_path: Path) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "guardana-recipe.lock.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return read_lock(path)

    ignored = unread_keys(lock_to_dict(_lock()), read, root="lock", refusal=RecipeError)

    assert not ignored, "lock keys that change nothing when deleted:\n  " + "\n  ".join(ignored)


def test_the_published_lock_schema_requires_every_key_the_writer_emits() -> None:
    document = lock_to_dict(_lock())
    validator = _validator("recipe-lock-v2.schema.json")
    dynamic = {
        "rules.acme.suite",
        "evaluators.llm_judge",
        "skipped.acme.tools",
        "subject_files.adapter",
        "sources.acme-helpers",
        "unpinned.rule:acme.suite",
    }

    unrequired = [
        render(path, "lock")
        for path in key_paths(document)
        if isinstance(path[-1], str)
        and render(path, "lock").removeprefix("lock.") not in dynamic
        and not list(validator.iter_errors(without(document, path)))
    ]

    assert not unrequired, f"keys the writer emits that the schema does not require: {unrequired}"
