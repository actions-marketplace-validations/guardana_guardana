"""A GenAI message event whose exporter dropped attributes is content that could not be read."""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.core.trace import read_trace


def _read_event(tmp_path: Path, event: dict[str, Any]) -> int:
    record = {
        "name": "chat",
        "context": {"trace_id": "tr-1", "span_id": "sp-1"},
        "attributes": {"gen_ai.operation.name": "chat"},
        "events": [event],
    }
    path = tmp_path / "otel.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    return read_trace(path).trace.unreadable


def test_control_a_message_event_read_in_full_leaves_nothing_unreadable(tmp_path: Path) -> None:
    event = {"name": "gen_ai.user.message", "attributes": {"role": "user", "content": "hi"}}

    assert _read_event(tmp_path, event) == 0


@pytest.mark.parametrize("counter", ["droppedAttributesCount", "dropped_attributes_count"])
@pytest.mark.parametrize(
    "event",
    [
        {"name": "gen_ai.user.message", "attributes": {"role": "user"}},
        {"name": "gen_ai.choice", "body": {"content": "hi"}},
    ],
    ids=["content-attribute-missing", "body-kept"],
)
def test_a_message_event_that_dropped_attributes_is_counted_unreadable(
    tmp_path: Path, counter: str, event: dict[str, Any]
) -> None:
    assert _read_event(tmp_path, {**event, counter: 1}) == 1


def test_an_event_with_no_content_and_a_drop_counter_is_counted_once(tmp_path: Path) -> None:
    event = {"name": "gen_ai.user.message", "attributes": {}, "droppedAttributesCount": "2"}

    assert _read_event(tmp_path, event) == 1


def test_a_drop_counter_on_an_event_outside_the_message_conventions_is_not_counted(
    tmp_path: Path,
) -> None:
    event = {"name": "exception", "attributes": {}, "droppedAttributesCount": 1}

    assert _read_event(tmp_path, event) == 0
