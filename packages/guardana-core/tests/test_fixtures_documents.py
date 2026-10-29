"""The fixtures file a team writes, walked key by key and held to its published schema.

A key whose deletion changes nothing is data the team believes it declared and the run
never held. Deleting each key in turn must be refused or read differently.
"""

import copy
import json
from collections.abc import Callable
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest
import yaml
from _fixtures_file import fixtures_document as document
from _roundtrip import Document, unread_keys
from guardana.core.fixtures import (
    _DOCUMENT_KEYS,
    _RECORD_KEYS,
    _TENANT_KEYS,
    _TOOL_KEYS,
    _TOP_KEYS,
    FIXTURES_SCHEMA_VERSION,
    FixturesError,
    load_fixtures,
)
from guardana.core.trace import SinkKind
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _validator() -> Draft202012Validator:
    schema: dict[str, Any] = json.loads(
        (_SCHEMAS / f"fixtures-v{FIXTURES_SCHEMA_VERSION}.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema)


def test_the_fixture_carries_every_key_the_loader_accepts() -> None:
    written = document()
    tenant_keys = {key for entry in written["tenants"].values() for key in entry}
    document_keys = {key for entry in written["documents"] for key in entry}
    record_keys = {key for entry in written["records"]["orders"] for key in entry}
    tool_keys = {key for entry in written["tools"].values() for key in entry}

    missing = (
        sorted(_TOP_KEYS - set(written))
        + sorted(f"tenants.*.{k}" for k in _TENANT_KEYS - tenant_keys - {"adapter"})
        + sorted(f"documents[].{k}" for k in _DOCUMENT_KEYS - document_keys)
        + sorted(f"records.*[].{k}" for k in _RECORD_KEYS - record_keys)
        + sorted(f"tools.*.{k}" for k in _TOOL_KEYS - tool_keys)
    )

    assert not missing, f"keys the loader accepts and this fixture never uses: {missing}"


def test_no_key_of_a_fixtures_file_can_be_deleted_without_the_loader_noticing(
    tmp_path: Path,
) -> None:
    def read(written: Document) -> object:
        path = tmp_path / "guardana-fixtures.yaml"
        path.write_text(yaml.safe_dump(written), encoding="utf-8")
        loaded = load_fixtures(path)
        return tuple(
            getattr(loaded, f.name) for f in fields(loaded) if f.name not in {"path", "digest"}
        )

    ignored = unread_keys(document(), read, root="fixtures", refusal=FixturesError)

    assert not ignored, "fixtures keys that change nothing when deleted:\n  " + "\n  ".join(ignored)


def test_the_published_schema_accepts_what_the_loader_reads() -> None:
    assert list(_validator().iter_errors(document())) == []


def test_the_schema_names_exactly_the_sinks_a_trace_records() -> None:
    schema = json.loads(
        (_SCHEMAS / f"fixtures-v{FIXTURES_SCHEMA_VERSION}.schema.json").read_text(encoding="utf-8")
    )
    tool = schema["properties"]["tools"]["additionalProperties"]

    assert tool["properties"]["sink"]["enum"] == [kind.value for kind in SinkKind]


_BREAKAGES: dict[str, Callable[[dict[str, Any]], object]] = {
    "one tenant": lambda d: d["tenants"].pop("globex"),
    "a tenant naming both": lambda d: d["tenants"]["acme"].update(adapter="a.yaml"),
    "a tenant naming neither": lambda d: d["tenants"].update(acme={}),
    "data not synthetic": lambda d: d.update(data="production"),
    "an update without a sink": lambda d: d["tools"]["refund_order"].pop("sink"),
    "a read with a sink": lambda d: d["tools"]["lookup_order"].update(sink="db"),
    "a sink no trace records": lambda d: d["tools"]["refund_order"].update(sink="payments"),
    "a send with a collection": lambda d: d["tools"]["send_email"].update(collection="orders"),
    "a record typing reference_code": lambda d: d["records"]["orders"][0]["fields"].update(
        reference_code="AB12-CD34"
    ),
    "an empty collection": lambda d: d["records"].update(orders=[]),
    "no documents and no records": lambda d: [d.pop(k) for k in ("documents", "records", "tools")],
    "a newer schema": lambda d: d.update(schema_version=2),
}


@pytest.mark.parametrize("change", _BREAKAGES)
def test_the_schema_refuses_what_the_loader_refuses(tmp_path: Path, change: str) -> None:
    written = copy.deepcopy(document())
    _BREAKAGES[change](written)
    path = tmp_path / "guardana-fixtures.yaml"
    path.write_text(yaml.safe_dump(written), encoding="utf-8")

    with pytest.raises(FixturesError):
        load_fixtures(path)
    assert list(_validator().iter_errors(written)), f"the schema accepts {change}"
