"""An envelope that leaves out the result channels its version requires is never stored as empty."""

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.store import InMemoryStore
from test_envelope_schema import _validator

_HISTORICAL = (
    Path(__file__).resolve().parents[2] / "guardana-core" / "tests" / "historical" / "envelope"
)
_OK = 200
_UNPROCESSABLE = 422


def _v8() -> dict[str, Any]:
    document: dict[str, Any] = json.loads((_HISTORICAL / "0.13.0.json").read_text(encoding="utf-8"))
    assert document["schema_version"] == 8
    assert document["findings"], "the fixture carries a finding to lose"
    return document


def _without_channels() -> dict[str, Any]:
    document = _v8()
    for channel in ("findings", "unverified", "errors"):
        del document[channel]
    return document


def _post(document: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))
    status = client.post("/findings", json=document).status_code
    return status, client.get("/findings").json()


def test_control_the_published_schema_refuses_the_envelope_without_its_channels() -> None:
    errors = list(_validator().iter_errors(_without_channels()))

    assert {error.validator for error in errors} == {"required"}


def test_control_the_whole_v8_envelope_is_stored() -> None:
    status, _ = _post(_v8())

    assert status == _OK


def test_ingest_refuses_a_v8_envelope_without_its_result_channels() -> None:
    status, stored = _post(_without_channels())

    assert status == _UNPROCESSABLE, [(row["summary"], row["findings"]) for row in stored]


def test_ingest_refuses_a_v8_envelope_without_its_summary() -> None:
    """Without a summary the dashboard would read no rule as skipped and no coverage as missing."""
    document = _v8()
    del document["summary"]
    assert {error.validator for error in _validator().iter_errors(document)} == {"required"}

    status, _ = _post(document)

    assert status == _UNPROCESSABLE
