"""A saved run of the current schema that lost a channel, or miscounts one, is refused."""

import json
from pathlib import Path
from typing import Any

import pytest
from _documents import run_manifest, saved_run_at_v17, scan_result
from guardana.core.report.load import (
    _REQUIRED_FIELDS,
    ReportLoadError,
    load_report,
    report_from_dict,
)
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from guardana.core.report.serialize import run_to_dict

_CHANNELS = ("findings", "unverified", "waived", "errors", "observations", "assessments")


def _consistent() -> dict[str, Any]:
    """A current-schema run whose summary counts exactly what its channels hold."""
    return run_to_dict(scan_result(), run_manifest())


def _saved(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_run_whose_summary_counts_its_channels_loads(tmp_path: Path) -> None:
    assert load_report(_saved(tmp_path, _consistent())).result.errors


@pytest.mark.parametrize("channel", _CHANNELS)
def test_a_current_run_missing_a_channel_is_refused_not_read_as_empty(
    tmp_path: Path, channel: str
) -> None:
    document = _consistent()
    del document[channel]

    with pytest.raises(ReportLoadError, match=f"has no {channel}"):
        load_report(_saved(tmp_path, document))


@pytest.mark.parametrize("channel", _CHANNELS)
def test_a_current_run_whose_channel_disagrees_with_its_summary_is_refused(
    tmp_path: Path, channel: str
) -> None:
    document = _consistent()
    document[channel] = []

    with pytest.raises(ReportLoadError, match=f"{channel} holds 0 where"):
        load_report(_saved(tmp_path, document))


def test_an_older_run_missing_a_channel_keeps_its_migrated_reading(tmp_path: Path) -> None:
    older = saved_run_at_v17(_consistent())
    del older["observations"]

    assert load_report(_saved(tmp_path, older)).result.observations == ()


def test_a_parsed_document_is_read_exactly_as_the_file_is(tmp_path: Path) -> None:
    document = _consistent()

    assert report_from_dict(document, Path("run.json")) == load_report(_saved(tmp_path, document))


_SCHEMA = (
    Path(__file__).resolve().parents[3] / "schemas" / f"run-v{REPORT_SCHEMA_VERSION}.schema.json"
)


def _required_by_the_schema() -> dict[tuple[str, ...], tuple[str, ...]]:
    """Every required key list of the published schema, by the object holding it."""
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    definitions = schema["$defs"]

    def resolved(node: dict[str, Any]) -> dict[str, Any]:
        while "$ref" in node:
            node = definitions[node["$ref"].rsplit("/", 1)[1]]
        return node

    run = resolved(schema["properties"]["run"])
    required = {(): tuple(schema["required"]), ("run",): tuple(run["required"])}
    for name, node in run["properties"].items():
        block = resolved(node)
        if "required" in block and block.get("type") == "object":
            required[("run", name)] = tuple(block["required"])
    return required


def test_the_reader_requires_exactly_what_the_published_schema_does() -> None:
    assert _required_by_the_schema() == _REQUIRED_FIELDS


def _paths() -> list[tuple[str, ...]]:
    return [(*where, key) for where, keys in _REQUIRED_FIELDS.items() for key in keys]


@pytest.mark.parametrize("missing", _paths(), ids=".".join)
def test_a_current_run_missing_a_required_key_is_refused(
    tmp_path: Path, missing: tuple[str, ...]
) -> None:
    document = _consistent()
    holder = document
    for key in missing[:-1]:
        holder = holder[key]
    if not isinstance(holder, dict) or missing[-1] not in holder:
        pytest.fail(f"the fixture run does not hold {'.'.join(missing)}")
    del holder[missing[-1]]

    with pytest.raises(ReportLoadError, match=rf"has no [^;]*\b{'.'.join(missing)}\b"):
        load_report(_saved(tmp_path, document))


def test_a_run_of_a_target_that_reads_no_files_has_a_null_scope(tmp_path: Path) -> None:
    document = _consistent()
    document["run"]["target"]["capabilities"] = ["chat"]
    document["scope"] = None

    assert load_report(_saved(tmp_path, document)).result.scope is None
