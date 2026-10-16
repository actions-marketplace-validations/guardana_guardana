"""A reply read out of an event stream is the response to the request, read whole, or none.

A streamable-HTTP server may answer with `text/event-stream`, carrying its own requests
and notifications beside the response. Only a complete event answering the pending
request is the reply; adopting any other would grade an answer nobody asked for.
"""

import json
from collections.abc import Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.target._mcp_http import MAX_RESPONSE_BYTES, McpError, RawReply, json_text

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)


def _event(message: Mapping[str, object]) -> str:
    return f"event: message\ndata: {json.dumps(message)}\n\n"


def _response(request_id: object, tools: list[str]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}


def _stream(*events: str) -> bytes:
    return "".join(events).encode("utf-8")


def test_the_event_answering_the_request_is_read_wherever_it_sits() -> None:
    raw = _stream(_event(_response(1, ["asked"])), _event(_response("stray", ["stray"])))

    assert json.loads(json_text(raw, 1))["result"] == {"tools": ["asked"]}


def test_a_stream_answering_only_another_request_is_refused() -> None:
    raw = _stream(_event(_response("stray", ["stray"])))

    with pytest.raises(McpError, match="request 1"):
        json_text(raw, 1)


def test_an_id_of_another_type_does_not_answer_the_request() -> None:
    raw = _stream(_event(_response("1", ["text id"])), _event(_response(True, ["bool id"])))

    with pytest.raises(McpError):
        json_text(raw, 1)


def test_two_responses_to_one_request_are_refused() -> None:
    raw = _stream(_event(_response(1, ["first"])), _event(_response(1, ["second"])))

    with pytest.raises(McpError):
        json_text(raw, 1)


def test_without_an_id_a_stream_must_hold_exactly_one_response() -> None:
    one = _stream(_event(_response(4, ["only"])))
    two = _stream(_event(_response(4, ["first"])), _event(_response(5, ["second"])))

    assert json.loads(json_text(one))["result"] == {"tools": ["only"]}
    with pytest.raises(McpError):
        json_text(two)


def test_the_servers_own_messages_beside_the_response_are_skipped() -> None:
    progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    raw = _stream(_event(progress), _event(ping), _event(_response(1, ["asked"])))

    assert json.loads(json_text(raw, 1))["result"] == {"tools": ["asked"]}
    assert json.loads(json_text(raw))["result"] == {"tools": ["asked"]}


def test_an_event_the_stream_stops_inside_is_not_read() -> None:
    cut = _event(_response(1, ["unfinished"])).rstrip("\n") + "\n"

    with pytest.raises(McpError):
        json_text(_stream(cut), 1)


def test_data_split_over_lines_and_line_endings_is_joined_as_one_event() -> None:
    raw = b'data: {"jsonrpc": "2.0", "id": 1,\r\ndata: "result": {"tools": []}}\r\n\r\n'

    assert json.loads(json_text(raw, 1)) == {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}


def test_a_bare_json_body_is_read_as_it_is() -> None:
    raw = json.dumps(_response(1, ["bare"])).encode()

    assert json.loads(json_text(raw, 1))["result"] == {"tools": ["bare"]}


def test_a_body_longer_than_the_read_ceiling_is_no_json_object() -> None:
    document = b'{"name": "card"}'
    whole = RawReply(200, {}, document + b" " * (MAX_RESPONSE_BYTES - len(document)))
    cut = RawReply(200, {}, document + b" " * (MAX_RESPONSE_BYTES + 1 - len(document)))

    assert whole.json_object() == {"name": "card"}
    assert cut.json_object() is None


def test_a_stream_with_no_response_is_no_json_object() -> None:
    reply = RawReply(200, {}, _stream(_event(_response("stray", []))))

    assert reply.json_object(1) is None
