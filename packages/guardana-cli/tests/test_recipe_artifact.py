"""A recipe's artifact directory never shows a green its run did not produce."""

import json
from pathlib import Path
from xml.etree.ElementTree import fromstring

import pytest
from guardana.cli._artifact import (
    ARTIFACT_SCHEMA_VERSION,
    MARKER,
    ArtifactRefusedError,
    claim,
    publish,
)
from jsonschema import Draft202012Validator

_SCHEMA = Path(__file__).resolve().parents[3] / "schemas" / "artifact-v1.schema.json"


def test_a_claimed_directory_says_the_run_did_not_finish_in_every_file(tmp_path: Path) -> None:
    out = tmp_path / "artifact"

    claim(out, "support-bot")

    suite = fromstring((out / "junit.xml").read_text(encoding="utf-8"))  # noqa: S314 — our own output
    assert suite.get("errors") == "1"
    assert "has not finished" in (out / "report.txt").read_text(encoding="utf-8")
    assert json.loads((out / MARKER).read_text(encoding="utf-8"))["status"] == "incomplete"


def test_a_published_run_replaces_every_file_of_the_previous_one(tmp_path: Path) -> None:
    out = tmp_path / "artifact"
    publish(out, {"run.json": "{}", "run.exchanges.jsonl": "old"}, status="complete")
    claim(out, "support-bot")

    publish(out, {"run.json": '{"new": true}'}, status="complete")

    assert sorted(p.name for p in out.iterdir()) == [MARKER, "run.json"]
    assert [p.name for p in tmp_path.iterdir()] == ["artifact"]


def test_a_directory_guardana_did_not_write_is_refused_and_left_alone(tmp_path: Path) -> None:
    out = tmp_path / "artifact"
    out.mkdir()
    (out / "notes.md").write_text("mine", encoding="utf-8")

    with pytest.raises(ArtifactRefusedError, match="did not write"):
        claim(out, "support-bot")

    assert (out / "notes.md").read_text(encoding="utf-8") == "mine"


def test_a_symlinked_output_directory_is_refused(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "artifact").symlink_to(elsewhere)

    with pytest.raises(ArtifactRefusedError, match="plain directory"):
        claim(tmp_path / "artifact", "support-bot")


def test_the_index_matches_its_published_schema_and_names_the_version_it_writes(
    tmp_path: Path,
) -> None:
    out = tmp_path / "artifact"
    publish(out, {"run.json": "{}"}, status="complete")
    index = json.loads((out / MARKER).read_text(encoding="utf-8"))
    validator = Draft202012Validator(json.loads(_SCHEMA.read_text(encoding="utf-8")))

    assert index["schema_version"] == ARTIFACT_SCHEMA_VERSION
    assert list(validator.iter_errors(index)) == []
    for key in index:
        assert list(validator.iter_errors({k: v for k, v in index.items() if k != key})), key


def test_a_file_dropped_into_an_artifact_after_a_run_is_never_deleted(tmp_path: Path) -> None:
    out = tmp_path / "artifact"
    publish(out, {"run.json": "{}"}, status="complete")
    (out / "my-notes.md").write_text("mine", encoding="utf-8")

    with pytest.raises(ArtifactRefusedError, match=r"my-notes\.md"):
        claim(out, "support-bot")

    assert (out / "my-notes.md").read_text(encoding="utf-8") == "mine"
