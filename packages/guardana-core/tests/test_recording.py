import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from guardana.core import recording as recording_module
from guardana.core.fingerprint import DigestKind
from guardana.core.manifest import SubjectKind
from guardana.core.recording import (
    RECORDING_FORMAT,
    RecordedExchange,
    Recording,
    RecordingError,
    RecordingOrigin,
    messages_key,
    read_recording,
    render_recording,
)
from guardana.core.redaction import holds_redaction_marker
from guardana.core.target import ChatMessage, Decline, DeclineReading, Target
from guardana.core.target._scoped import RuleScoped
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_SCHEMA = _SCHEMAS / "recording-v3.schema.json"
_V2_SCHEMA = _SCHEMAS / "recording-v2.schema.json"
_V1_SCHEMA = _SCHEMAS / "recording-v1.schema.json"
RULE = "acme.support.refund_policy"
OTHER_RULE = "acme.support.tone"
KEY = "sha256:" + "0" * 64
HEADER: dict[str, Any] = {
    "guardana_recording": RECORDING_FORMAT,
    "name": "support-replies",
    "version": "2026.10",
    "verbatim": True,
}
LINE: dict[str, Any] = {
    "rule": RULE,
    "input": "Can I return a gift?",
    "reply": "Yes, within 30 days.",
}
DECLINED_LINE: dict[str, Any] = {
    "rule": RULE,
    "input": "How do I pick a lock?",
    "declined": {"name": "content_filter", "reading": "refusal", "status": 400},
    "meta": {"guard_category": "weapons", "request_id": "req-7"},
}
CONTENT_FILTER = Decline("content_filter", DeclineReading.REFUSAL, 400)


def _write(path: Path, *records: object, raw_lines: tuple[str, ...] = ()) -> Path:
    lines = [json.dumps(record) for record in records] + list(raw_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _refusal(path: Path) -> str:
    with pytest.raises(RecordingError) as caught:
        read_recording(path)
    return str(caught.value)


def _validator(path: Path = _SCHEMA) -> Draft202012Validator:
    schema: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _full_recording() -> Recording:
    """A recording with every optional field occupied, so a round trip proves each one."""
    return Recording(
        name="support-replies",
        version="2026.10",
        verbatim=True,
        subject="support-bot staging",
        subject_kind=SubjectKind.MODEL_HARNESS,
        origin=RecordingOrigin(
            run_id="run-1",
            target="https://bot.invalid/v1",
            started_at="2026-10-01T09:00:00Z",
            stopped_by="budget",
            gate="high",
            trials={RULE: 2, OTHER_RULE: 1},
            rules=(RULE, OTHER_RULE, "acme.support.unreached"),
        ),
        exchanges=(
            RecordedExchange(
                rule=RULE,
                input=(
                    ChatMessage(role="system", content="You answer refund questions."),
                    ChatMessage(role="user", content="Can I return a gift? Zażółć"),
                ),
                reply="Yes, within 30 days.\nKeep the receipt.",
                key=KEY,
                altered=True,
            ),
            RecordedExchange(
                rule=RULE,
                input=(ChatMessage(role="user", content="Can I return a gift? Zażółć"),),
                reply="",
            ),
            RecordedExchange(
                rule=OTHER_RULE,
                input=(
                    ChatMessage(role="user", content="hi"),
                    ChatMessage(role="assistant", content="Hello."),
                    ChatMessage(role="user", content="thanks"),
                ),
                reply="You are welcome.",
                meta={"request_id": "req-1", "guard_category": "none"},
            ),
            RecordedExchange(
                rule=RULE,
                input=(ChatMessage(role="user", content="How do I pick a lock?"),),
                reply=None,
                key=KEY,
                declined=CONTENT_FILTER,
                meta={"guard_category": "weapons"},
            ),
        ),
        digest=None,
    )


def _as_written(recording: Recording) -> Recording:
    """The recording without what only a read supplies: line numbers and the file digest."""
    return replace(
        recording,
        digest=None,
        exchanges=tuple(replace(exchange, line=0) for exchange in recording.exchanges),
    )


def test_a_rendered_recording_reads_back_as_the_recording_it_was(tmp_path: Path) -> None:
    original = _full_recording()
    path = tmp_path / "replies.jsonl"
    path.write_text(render_recording(original), encoding="utf-8")

    loaded = read_recording(path)

    assert _as_written(loaded) == original
    assert [exchange.line for exchange in loaded.exchanges] == [2, 3, 4, 5]
    assert loaded.identity == "support-replies@2026.10"
    assert loaded.rules == frozenset({RULE, OTHER_RULE, "acme.support.unreached"})


def test_a_minimal_recording_round_trips_without_optional_fields(tmp_path: Path) -> None:
    original = Recording(
        name="n",
        version="1",
        verbatim=False,
        subject=None,
        origin=RecordingOrigin(
            run_id="r", target="t", started_at=None, stopped_by=None, gate=None, trials={}, rules=()
        ),
        exchanges=(RecordedExchange(rule=RULE, input=(ChatMessage("user", "q"),), reply="a"),),
        digest=None,
    )
    path = tmp_path / "minimal.jsonl"
    path.write_text(render_recording(original), encoding="utf-8")

    assert _as_written(read_recording(path)) == original


def test_rendering_is_deterministic_and_omits_what_is_absent() -> None:
    minimal = Recording(
        name="n",
        version="1",
        verbatim=True,
        subject=None,
        origin=None,
        exchanges=(RecordedExchange(rule=RULE, input=(ChatMessage("user", "żółw"),), reply="a"),),
        digest=None,
    )

    text = render_recording(minimal)

    assert text == render_recording(minimal)
    assert text == (
        '{"guardana_recording":3,"name":"n","version":"1","verbatim":true}\n'
        '{"rule":"acme.support.refund_policy","input":[{"role":"user","content":"żółw"}],'
        '"reply":"a"}\n'
    )


def test_every_rendered_line_validates_against_the_published_schema() -> None:
    validator = _validator()
    for line in render_recording(_full_recording()).splitlines():
        assert not list(validator.iter_errors(json.loads(line))), line


def test_the_schema_describes_the_format_this_build_writes() -> None:
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))

    assert schema["$defs"]["header"]["properties"]["guardana_recording"]["const"] == (
        RECORDING_FORMAT
    )


def test_a_format_2_recording_still_validates_against_the_v2_schema() -> None:
    validator = _validator(_V2_SCHEMA)
    header = {**HEADER, "guardana_recording": 2, "subject_kind": "application"}

    for record in (header, LINE):
        assert not list(validator.iter_errors(record)), record
    assert list(validator.iter_errors(DECLINED_LINE))
    assert list(validator.iter_errors(HEADER))


def test_a_format_1_recording_still_validates_against_the_v1_schema() -> None:
    validator = _validator(_V1_SCHEMA)
    header = {**HEADER, "guardana_recording": 1, "subject": "bot"}

    for record in (header, LINE):
        assert not list(validator.iter_errors(record)), record
    assert list(validator.iter_errors({**header, "subject_kind": "application"}))
    assert list(validator.iter_errors(HEADER))


@pytest.mark.parametrize(
    "record",
    [
        {"guardana_recording": 1, "name": "n", "version": "1", "verbatim": True},
        {"guardana_recording": 2, "name": "n", "version": "1", "verbatim": True},
        {"guardana_recording": 4, "name": "n", "version": "1", "verbatim": True},
        {"guardana_recording": 2, "name": "n", "version": "1"},
        {"guardana_recording": 2, "name": "n", "version": "1", "verbatim": "true"},
        {"guardana_recording": 2, "name": "", "version": "1", "verbatim": True},
        {"guardana_recording": 2, "name": "n", "version": "1", "verbatim": True, "extra": 1},
        {**HEADER, "subject_kind": ""},
        {**HEADER, "subject_kind": "service"},
        {"rule": RULE, "input": "q"},
        {"rule": RULE, "input": [], "reply": "a"},
        {"rule": RULE, "input": [{"role": "tool", "content": "x"}], "reply": "a"},
        {"rule": RULE, "input": "q", "reply": "a", "key": "sha256:abc"},
        {"rule": RULE, "input": "q", "reply": "a", "altered": "yes"},
        {"rule": RULE, "input": "q", "reply": "a", "answer": "a"},
        {**DECLINED_LINE, "reply": "blocked"},
        {**DECLINED_LINE, "altered": True},
        {**DECLINED_LINE, "declined": {"name": "f", "reading": "refusal", "status": 429}},
        {**DECLINED_LINE, "declined": {"name": "f", "reading": "refusal", "status": 503}},
        {**DECLINED_LINE, "declined": {"name": "f", "reading": "blocked", "status": 400}},
        {**DECLINED_LINE, "declined": {"name": "F!", "reading": "refusal", "status": 400}},
        {**DECLINED_LINE, "declined": {"name": "f", "reading": "refusal"}},
        {**DECLINED_LINE, "meta": {"Guard": "x"}},
        {**DECLINED_LINE, "meta": {"guard": 1}},
    ],
)
def test_the_schema_refuses_the_shapes_the_reader_refuses(record: dict[str, Any]) -> None:
    assert list(_validator().iter_errors(record))


def test_a_header_rule_supplies_the_rule_for_lines_that_name_none(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "r.jsonl",
        {**HEADER, "rule": RULE},
        {"input": "q", "reply": "a"},
        {"rule": OTHER_RULE, "input": "q", "reply": "b"},
    )

    loaded = read_recording(path)

    assert [exchange.rule for exchange in loaded.exchanges] == [RULE, OTHER_RULE]
    assert loaded.exchanges[0].input == (ChatMessage(role="user", content="q"),)


def test_the_digest_is_the_sha256_of_the_file_bytes(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, LINE)
    data = path.read_bytes()

    loaded = read_recording(path)

    assert loaded.digest is not None
    assert loaded.digest.digest == f"sha256:{hashlib.sha256(data).hexdigest()}"
    assert loaded.digest.kind is DigestKind.CONTENT
    assert loaded.digest.bytes == len(data)


def test_a_line_without_a_rule_is_refused_when_the_header_names_none(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {"input": "q", "reply": "a"})

    assert f"{path}:2:" in _refusal(path)


def test_a_missing_verbatim_is_refused(tmp_path: Path) -> None:
    header = {key: value for key, value in HEADER.items() if key != "verbatim"}
    path = _write(tmp_path / "r.jsonl", header, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert "verbatim" in message


def test_a_verbatim_written_as_a_string_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "verbatim": "true"}, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert "verbatim" in message


def test_another_format_is_refused_naming_the_formats_this_build_reads(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "guardana_recording": 4}, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert "recording format 4" in message
    assert "reads formats 1, 2 and 3" in message


def test_a_declined_line_reads_as_the_decline_with_its_metadata(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, DECLINED_LINE)

    (exchange,) = read_recording(path).exchanges

    assert exchange.reply is None
    assert exchange.declined == CONTENT_FILTER
    assert exchange.meta == {"guard_category": "weapons", "request_id": "req-7"}
    assert not exchange.altered


def test_a_declined_line_is_never_altered(tmp_path: Path) -> None:
    recording = read_recording(
        _write(tmp_path / "r.jsonl", {**HEADER, "verbatim": False}, DECLINED_LINE)
    )

    assert not recording.reply_altered(recording.exchanges[0])


@pytest.mark.parametrize(
    ("line", "names"),
    [
        ({**DECLINED_LINE, "reply": "blocked"}, "both `reply` and `declined`"),
        ({**DECLINED_LINE, "altered": True}, "never `altered`"),
        ({"rule": RULE, "input": "q"}, "`reply` must be a string"),
        (
            {**DECLINED_LINE, "declined": {"name": "f", "reading": "refusal", "status": 429}},
            "`declined.status`",
        ),
        (
            {**DECLINED_LINE, "declined": {"name": "f", "reading": "blocked", "status": 400}},
            "`declined.reading`",
        ),
        (
            {**DECLINED_LINE, "declined": {"name": "F", "reading": "refusal", "status": 400}},
            "`declined.name`",
        ),
        (
            {
                **DECLINED_LINE,
                "declined": {"name": "f", "reading": "refusal", "status": 400, "x": 1},
            },
            "unknown `declined` key",
        ),
        ({**DECLINED_LINE, "meta": {"Guard": "x"}}, "`meta` name"),
        ({**DECLINED_LINE, "meta": {"guard": 1}}, "`meta.guard`"),
        ({**DECLINED_LINE, "meta": {f"n{i}": "x" for i in range(17)}}, "more than 16"),
    ],
)
def test_a_malformed_decline_or_metadata_is_refused_by_its_line(
    tmp_path: Path, line: dict[str, Any], names: str
) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, line)

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert names in message


@pytest.mark.parametrize("key", ["declined", "meta"])
def test_a_format_2_line_carrying_a_format_3_key_is_refused(tmp_path: Path, key: str) -> None:
    line = {"rule": RULE, "input": "q", key: DECLINED_LINE[key]}
    if key == "meta":
        line["reply"] = "a"
    path = _write(tmp_path / "r.jsonl", {**HEADER, "guardana_recording": 2}, line)

    message = _refusal(path)

    assert f"{path}:2: unknown line key(s) {key};" in message


def test_an_exchange_holds_exactly_one_of_a_reply_and_a_decline() -> None:
    asked = (ChatMessage("user", "q"),)
    with pytest.raises(ValueError, match="exactly one"):
        RecordedExchange(rule=RULE, input=asked, reply="a", declined=CONTENT_FILTER)
    with pytest.raises(ValueError, match="exactly one"):
        RecordedExchange(rule=RULE, input=asked, reply=None)
    with pytest.raises(ValueError, match="no reply to alter"):
        RecordedExchange(rule=RULE, input=asked, reply=None, declined=CONTENT_FILTER, altered=True)


def test_a_recording_with_a_subject_kind_is_written_in_the_current_format_and_reads_back(
    tmp_path: Path,
) -> None:
    original = replace(_full_recording(), subject_kind=SubjectKind.APPLICATION)
    path = tmp_path / "kind.jsonl"
    path.write_text(render_recording(original), encoding="utf-8")

    header = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    loaded = read_recording(path)

    assert header["guardana_recording"] == RECORDING_FORMAT == 3
    assert header["subject_kind"] == "application"
    assert loaded.subject_kind is SubjectKind.APPLICATION
    assert _as_written(loaded) == original


def test_a_recording_without_a_subject_kind_is_written_without_the_key() -> None:
    text = render_recording(replace(_full_recording(), subject_kind=None))

    assert "subject_kind" not in json.loads(text.splitlines()[0])


def test_a_format_1_recording_reads_as_declaring_no_subject_kind(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "guardana_recording": 1}, LINE)
    data = path.read_bytes()

    loaded = read_recording(path)

    assert loaded.subject_kind is None
    assert loaded.exchanges[0].reply == LINE["reply"]
    assert loaded.digest is not None
    assert loaded.digest.digest == f"sha256:{hashlib.sha256(data).hexdigest()}"


def test_a_format_1_header_carrying_a_subject_kind_is_refused(tmp_path: Path) -> None:
    header = {**HEADER, "guardana_recording": 1, "subject_kind": "application"}
    path = _write(tmp_path / "r.jsonl", header, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert "subject_kind" in message


@pytest.mark.parametrize("kind", ["service", "", 1, None])
def test_a_subject_kind_that_is_not_a_known_kind_is_refused(tmp_path: Path, kind: object) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "subject_kind": kind}, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert "subject_kind" in message
    assert "application, model_harness" in message


def test_a_boolean_format_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "guardana_recording": True}, LINE)

    assert f"{path}:1:" in _refusal(path)


def test_a_file_that_does_not_open_with_a_header_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", LINE)

    assert f"{path}:1:" in _refusal(path)


def test_a_file_with_no_header_at_all_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    path.write_text("\n\n", encoding="utf-8")

    assert "no header" in _refusal(path)


def test_a_header_and_no_lines_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER)

    assert "no exchanges" in _refusal(path)


@pytest.mark.parametrize("field", ["name", "version"])
def test_a_blank_name_or_version_is_refused(tmp_path: Path, field: str) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, field: "  "}, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert field in message


def test_an_unknown_header_key_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "dataset": "x"}, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert "dataset" in message


def test_an_unknown_line_key_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "answer": "x"})

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "answer" in message


def test_a_repeated_key_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "r.jsonl",
        HEADER,
        raw_lines=(f'{{"rule": "{RULE}", "input": "q", "reply": "a", "reply": "b"}}',),
    )

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "reply" in message


def test_a_line_that_is_not_json_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, raw_lines=("{not json",))

    assert f"{path}:2:" in _refusal(path)


def test_a_line_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, raw_lines=('["q", "a"]',))

    assert f"{path}:2:" in _refusal(path)


def test_a_line_without_a_reply_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {"rule": RULE, "input": "q"})

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "reply" in message


def test_a_reply_that_is_not_a_string_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "reply": None})

    assert f"{path}:2:" in _refusal(path)


def test_an_empty_reply_is_read_as_what_the_application_said(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "reply": ""})

    assert read_recording(path).exchanges[0].reply == ""


def test_a_line_without_an_input_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {"rule": RULE, "reply": "a"})

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "input" in message


def test_a_blank_string_input_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "input": " "})

    assert f"{path}:2:" in _refusal(path)


def test_an_empty_message_list_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "input": []})

    assert f"{path}:2:" in _refusal(path)


def test_messages_that_do_not_end_on_the_user_are_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "r.jsonl",
        HEADER,
        {
            **LINE,
            "input": [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": "a"},
            ],
        },
    )

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "user" in message


def test_a_tool_role_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "r.jsonl", HEADER, {**LINE, "input": [{"role": "tool", "content": "x"}]}
    )

    assert f"{path}:2:" in _refusal(path)


def test_a_message_content_that_is_not_a_string_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "input": [{"role": "user", "content": 3}]})

    assert f"{path}:2:" in _refusal(path)


def test_an_unknown_message_key_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "r.jsonl",
        HEADER,
        {**LINE, "input": [{"role": "user", "content": "q", "name": "x"}]},
    )

    assert f"{path}:2:" in _refusal(path)


@pytest.mark.parametrize("key", ["sha256:abc", "md5:" + "0" * 64, "sha256:" + "A" * 64, 7])
def test_a_key_that_is_not_a_sha256_digest_is_refused(tmp_path: Path, key: object) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "key": key})

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "key" in message


def test_an_altered_mark_that_is_not_a_boolean_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "altered": 1})

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "altered" in message


def test_a_blank_line_rule_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "rule": ""})

    assert f"{path}:2:" in _refusal(path)


def test_a_blank_header_subject_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "subject": ""}, LINE)

    assert f"{path}:1:" in _refusal(path)


def _origin(**overrides: object) -> dict[str, object]:
    origin: dict[str, object] = {
        "run_id": "run-1",
        "target": "https://bot.invalid/v1",
        "started_at": None,
        "stopped_by": None,
        "gate": None,
        "trials": {RULE: 1},
        "rules": [RULE],
    }
    origin.update(overrides)
    return origin


@pytest.mark.parametrize(
    ("origin", "named"),
    [
        (_origin(trials={RULE: 0}), "trials"),
        (_origin(trials={RULE: True}), "trials"),
        (_origin(trials=[RULE]), "trials"),
        (_origin(rules=[RULE, RULE]), "rules"),
        (_origin(rules="acme"), "rules"),
        (_origin(run_id=""), "run_id"),
        (_origin(gate=3), "gate"),
        (_origin(surprise=1), "surprise"),
        ({key: value for key, value in _origin().items() if key != "rules"}, "rules"),
        ("run-1", "origin"),
    ],
)
def test_a_malformed_origin_is_refused(tmp_path: Path, origin: object, named: str) -> None:
    path = _write(tmp_path / "r.jsonl", {**HEADER, "origin": origin}, LINE)

    message = _refusal(path)

    assert f"{path}:1:" in message
    assert named in message


def test_a_line_over_the_record_ceiling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recording_module, "MAX_RECORD_BYTES", 200)
    path = _write(tmp_path / "r.jsonl", HEADER, {**LINE, "reply": "x" * 300})

    message = _refusal(path)

    assert f"{path}:2:" in message
    assert "ceiling" in message


def test_a_file_over_the_size_ceiling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recording_module, "MAX_TRACE_BYTES", 100)
    path = _write(tmp_path / "r.jsonl", HEADER, LINE, LINE)

    assert "ceiling" in _refusal(path)


def test_more_lines_than_the_ceiling_are_refused_rather_than_cut_short(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recording_module, "MAX_EXCHANGES", 2)
    path = _write(tmp_path / "r.jsonl", HEADER, LINE, LINE, LINE)

    message = _refusal(path)

    assert f"{path}:4:" in message


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    path.write_bytes(
        json.dumps(HEADER).encode() + b"\n" + b'{"rule":"r","input":"\xff","reply":"a"}\n'
    )

    assert "UTF-8" in _refusal(path)


def test_a_file_that_cannot_be_read_is_refused(tmp_path: Path) -> None:
    assert "could not be read" in _refusal(tmp_path / "missing.jsonl")


def test_rendering_refuses_what_the_reader_would_refuse() -> None:
    unreadable = replace(
        _full_recording(),
        exchanges=(RecordedExchange(rule=RULE, input=(ChatMessage("assistant", "a"),), reply="b"),),
    )

    with pytest.raises(RecordingError, match="user"):
        render_recording(unreadable)


def test_rendering_refuses_a_recording_with_no_exchanges() -> None:
    with pytest.raises(RecordingError, match="no exchanges"):
        render_recording(replace(_full_recording(), exchanges=()))


def test_rendering_refuses_a_message_carrying_a_tool_call_id() -> None:
    with_tool = replace(
        _full_recording(),
        exchanges=(
            RecordedExchange(
                rule=RULE, input=(ChatMessage("user", "q", tool_call_id="c1"),), reply="a"
            ),
        ),
    )

    with pytest.raises(RecordingError, match="tool"):
        render_recording(with_tool)


def test_a_reply_is_altered_when_the_recording_is_not_verbatim() -> None:
    exchange = RecordedExchange(rule=RULE, input=(ChatMessage("user", "q"),), reply="plain")
    recording = replace(_full_recording(), verbatim=False, exchanges=(exchange,))

    assert recording.reply_altered(exchange)


def test_a_reply_is_altered_when_its_line_says_so() -> None:
    exchange = RecordedExchange(
        rule=RULE, input=(ChatMessage("user", "q"),), reply="plain", altered=True
    )
    recording = replace(_full_recording(), exchanges=(exchange,))

    assert recording.reply_altered(exchange)


def test_a_reply_holding_a_redaction_placeholder_is_altered() -> None:
    exchange = RecordedExchange(
        rule=RULE,
        input=(ChatMessage("user", "q"),),
        reply="Write to [redacted:email:0123456789ab] for help.",
    )
    recording = replace(_full_recording(), exchanges=(exchange,))

    assert recording.reply_altered(exchange)


def test_a_verbatim_unmarked_reply_without_a_placeholder_is_not_altered() -> None:
    exchange = RecordedExchange(
        rule=RULE, input=(ChatMessage("user", "q"),), reply="Write to [redacted] for help."
    )
    recording = replace(_full_recording(), exchanges=(exchange,))

    assert not recording.reply_altered(exchange)


@pytest.mark.parametrize(
    "text",
    [
        "key [redacted:github-token] here",
        "mail [redacted:email:0123456789ab]",
        "[evidence withheld: metadata_only]",
        "[evidence withheld: metadata_only:0123456789ab]",
        "[reason withheld: metadata_only]",
        "start… [truncated: evidence exceeded 16384 bytes]",
        "start… [truncated: evidence exceeded 16384 bytes; 0123456789ab]",
    ],
)
def test_a_placeholder_the_redactor_writes_is_recognised(text: str) -> None:
    assert holds_redaction_marker(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "nothing to see",
        "[redacted]",
        "[redacted:Email]",
        "[redacted:email:0123]",
        "[evidence withheld]",
        "[truncated: evidence exceeded many bytes]",
    ],
)
def test_text_without_a_redactor_placeholder_is_not_flagged(text: str) -> None:
    assert not holds_redaction_marker(text)


def test_equal_messages_have_equal_keys() -> None:
    first = (ChatMessage("system", "s"), ChatMessage("user", "q"))
    second = [ChatMessage("system", "s"), ChatMessage("user", "q")]

    assert messages_key(first) == messages_key(second)
    assert messages_key(first).startswith("sha256:")
    assert len(messages_key(first)) == len("sha256:") + 64


def test_a_different_role_gives_a_different_key() -> None:
    assert messages_key([ChatMessage("system", "q")]) != messages_key([ChatMessage("user", "q")])


def test_a_different_content_gives_a_different_key() -> None:
    assert messages_key([ChatMessage("user", "q")]) != messages_key([ChatMessage("user", "Q")])


def test_moving_a_boundary_between_messages_gives_a_different_key() -> None:
    split_late = [ChatMessage("user", "ab"), ChatMessage("user", "c")]
    split_early = [ChatMessage("user", "a"), ChatMessage("user", "bc")]

    assert messages_key(split_late) != messages_key(split_early)


def test_the_key_is_the_digest_of_a_fixed_canonical_encoding() -> None:
    """Pinned to bytes, so a key written by one build matches the messages in the next."""
    canonical = '[["user","żółw"]]'.encode()

    assert messages_key([ChatMessage("user", "żółw")]) == (
        f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    )


def test_a_target_offering_per_rule_views_satisfies_rule_scoped() -> None:
    class _Scoped:
        def for_rule(self, rule_id: str) -> Target:
            raise NotImplementedError(rule_id)

    class _Plain:
        pass

    assert isinstance(_Scoped(), RuleScoped)
    assert not isinstance(_Plain(), RuleScoped)


def test_render_refuses_a_recording_over_the_file_ceiling() -> None:
    reply = "z" * 1_000_000
    recording = Recording(
        name="n",
        version="1",
        verbatim=True,
        subject=None,
        origin=None,
        exchanges=tuple(
            RecordedExchange(rule="acme.rule", input=(ChatMessage("user", f"Q{n}?"),), reply=reply)
            for n in range(70)
        ),
        digest=None,
    )

    with pytest.raises(RecordingError, match="ceiling every reader applies"):
        render_recording(recording)
