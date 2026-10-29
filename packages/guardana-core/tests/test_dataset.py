import hashlib
import json
from pathlib import Path

import pytest
from guardana.core import dataset as dataset_module
from guardana.core.dataset import (
    DATASET_FORMAT,
    DatasetCase,
    DatasetError,
    RegressionPair,
    read_dataset,
    render_case,
    render_header,
    resolve_dataset_path,
)
from guardana.core.target import ChatMessage
from jsonschema import Draft202012Validator

HEADER = {"guardana_dataset": DATASET_FORMAT, "name": "support-golden", "version": "2026.09"}
STRING_CASE = {
    "input": "How do I reset my password?",
    "expect": {"contains_any": ["Settings", "reset link"]},
    "tags": ["account"],
}
MESSAGES_CASE = {
    "input": {
        "messages": [
            {"role": "system", "content": "You answer support questions."},
            {"role": "user", "content": "Where is my invoice?"},
        ]
    }
}


def _write(path: Path, *records: object, raw_lines: tuple[str, ...] = ()) -> Path:
    lines = [json.dumps(record) for record in records] + list(raw_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _refusal(path: Path, *, fixture: bool = False) -> str:
    with pytest.raises(DatasetError) as caught:
        read_dataset(path, fixture=fixture)
    return str(caught.value)


def test_a_good_dataset_loads_its_cases_and_identity(tmp_path: Path) -> None:
    path = tmp_path / "golden.jsonl"
    path.write_text(
        "\n".join([json.dumps(HEADER), "", json.dumps(STRING_CASE), json.dumps(MESSAGES_CASE)])
        + "\n",
        encoding="utf-8",
    )

    loaded = read_dataset(path)

    assert loaded.identity == "support-golden@2026.09"
    assert loaded.digest.startswith("sha256:")
    first, second = loaded.cases
    assert first.line == 3
    assert first.input == "How do I reset my password?"
    assert dict(first.expect) == {"contains_any": ["Settings", "reset link"]}
    assert first.tags == ("account",)
    assert first.reply is None
    assert second.line == 4
    assert second.input == (
        ChatMessage(role="system", content="You answer support questions."),
        ChatMessage(role="user", content="Where is my invoice?"),
    )
    assert dict(second.expect) == {}
    assert second.tags == ()


def test_the_digest_is_the_sha256_of_the_file_bytes_and_moves_with_one_byte(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE)
    before = read_dataset(path).digest

    path.write_bytes(path.read_bytes().replace(b"password", b"passwore"))

    assert read_dataset(path).digest == f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    assert read_dataset(path).digest != before


def test_a_fixture_dataset_keeps_each_cases_reply(tmp_path: Path) -> None:
    path = _write(tmp_path / "fixture.jsonl", HEADER, {**STRING_CASE, "reply": "Open Settings."})

    (case,) = read_dataset(path, fixture=True).cases

    assert case.reply == "Open Settings."


def test_a_reply_outside_a_fixture_dataset_is_refused_naming_its_line(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, "reply": "Open Settings."})

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "reply" in message


def test_a_file_with_no_header_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", STRING_CASE)

    message = _refusal(path)

    assert f"{path}:1" in message
    assert "header" in message


def test_an_empty_file_is_refused_for_its_missing_header(tmp_path: Path) -> None:
    path = tmp_path / "golden.jsonl"
    path.write_text("\n\n", encoding="utf-8")

    assert "header" in _refusal(path)


def test_a_header_with_an_extra_key_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", {**HEADER, "owner": "qa"}, STRING_CASE)

    message = _refusal(path)

    assert f"{path}:1" in message
    assert "owner" in message


def test_a_header_from_another_format_is_refused_as_another_version(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", {**HEADER, "guardana_dataset": 3}, STRING_CASE)

    message = _refusal(path)

    assert f"{path}:1" in message
    assert "another Guardana version" in message


def test_a_header_with_a_boolean_format_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", {**HEADER, "guardana_dataset": True}, STRING_CASE)

    assert f"{path}:1" in _refusal(path)


def test_a_header_with_an_empty_name_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", {**HEADER, "name": " "}, STRING_CASE)

    message = _refusal(path)

    assert f"{path}:1" in message
    assert "name" in message


def test_a_header_with_no_cases_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER)

    assert "no cases" in _refusal(path)


def test_an_unknown_case_key_is_refused_naming_its_line(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE, {**STRING_CASE, "weight": 2})

    message = _refusal(path)

    assert f"{path}:3" in message
    assert "weight" in message


def test_a_case_without_input_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {"tags": ["account"]})

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "input" in message


def test_an_empty_input_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {"input": ""})

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "input" in message


def test_messages_ending_on_the_assistant_are_refused(tmp_path: Path) -> None:
    case = {
        "input": {
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi, how can I help?"},
            ]
        }
    }
    path = _write(tmp_path / "golden.jsonl", HEADER, case)

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "user" in message


def test_a_message_with_an_unknown_role_is_refused(tmp_path: Path) -> None:
    case = {"input": {"messages": [{"role": "tool", "content": "{}"}]}}
    path = _write(tmp_path / "golden.jsonl", HEADER, case)

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "tool" in message


def test_a_message_with_empty_content_is_refused(tmp_path: Path) -> None:
    case = {"input": {"messages": [{"role": "user", "content": ""}]}}
    path = _write(tmp_path / "golden.jsonl", HEADER, case)

    assert f"{path}:2" in _refusal(path)


def test_an_expect_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, "expect": ["Settings"]})

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "expect" in message


def test_a_tag_in_the_reserved_sample_namespace_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, "tags": ["sample:7"]})

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "sample:" in message


def test_an_empty_tag_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, "tags": [""]})

    assert f"{path}:2" in _refusal(path)


def test_a_malformed_json_line_is_refused_naming_its_line(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE, raw_lines=('{"input": ',))

    message = _refusal(path)

    assert f"{path}:3" in message
    assert "JSON" in message


def test_a_line_that_is_not_an_object_is_refused_naming_its_line(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE, ["a", "list"])

    assert f"{path}:3" in _refusal(path)


def test_an_oversize_line_is_refused_naming_its_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    long_case = {"input": "x" * 200}
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE, long_case)
    monkeypatch.setattr(dataset_module, "MAX_RECORD_BYTES", 150)

    message = _refusal(path)

    assert f"{path}:3" in message
    assert "150" in message


def test_a_file_over_the_total_size_bound_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE, STRING_CASE)
    monkeypatch.setattr(dataset_module, "MAX_TRACE_BYTES", 100)

    assert "100" in _refusal(path)


def test_too_many_cases_are_refused_naming_the_first_line_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, STRING_CASE, STRING_CASE, STRING_CASE)
    monkeypatch.setattr(dataset_module, "MAX_CASES", 2)

    message = _refusal(path)

    assert f"{path}:4" in message
    assert "2" in message


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "golden.jsonl"
    path.write_bytes(json.dumps(HEADER).encode() + b"\n\xff\xfe\n")

    assert "UTF-8" in _refusal(path)


def test_a_missing_file_is_refused_as_a_dataset_error(tmp_path: Path) -> None:
    assert "could not be read" in _refusal(tmp_path / "absent.jsonl")


def test_a_relative_path_resolves_beside_the_rule_file(tmp_path: Path) -> None:
    rule = tmp_path / "rules" / "suite.yaml"
    (tmp_path / "rules" / "data").mkdir(parents=True)

    resolved = resolve_dataset_path("data/golden.jsonl", rule)

    assert resolved == (tmp_path / "rules" / "data" / "golden.jsonl").resolve()


def test_a_url_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="URL"):
        resolve_dataset_path("https://example.invalid/golden.jsonl", tmp_path / "suite.yaml")


def test_an_absolute_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="absolute"):
        resolve_dataset_path(str(tmp_path / "golden.jsonl"), tmp_path / "suite.yaml")


def test_a_parent_escape_is_refused(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()

    with pytest.raises(DatasetError, match="outside"):
        resolve_dataset_path("../golden.jsonl", tmp_path / "rules" / "suite.yaml")


def test_a_parent_step_that_stays_inside_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "rules" / "data").mkdir(parents=True)

    resolved = resolve_dataset_path("data/../golden.jsonl", tmp_path / "rules" / "suite.yaml")

    assert resolved == (tmp_path / "rules" / "golden.jsonl").resolve()


def test_a_symlink_escaping_the_rule_directory_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    _write(outside / "golden.jsonl", HEADER, STRING_CASE)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "golden.jsonl").symlink_to(outside / "golden.jsonl")

    with pytest.raises(DatasetError, match="symbolic link"):
        resolve_dataset_path("golden.jsonl", rules / "suite.yaml")


def test_an_empty_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DatasetError):
        resolve_dataset_path(" ", tmp_path / "suite.yaml")


def test_a_key_repeated_on_a_line_is_refused_rather_than_resolved_to_the_last(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path / "d.jsonl", HEADER, raw_lines=('{"input": "a", "input": "b"}',))
    assert _refusal(path).endswith("d.jsonl:2: the key input appears twice on the line")


PAIR_CASE = {
    **STRING_CASE,
    "tags": ["regression", "label:no-reset-link"],
    "observed": "I cannot help with passwords.",
    "accepted": "Open Settings and request a reset link.",
}
_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _validator(version: int) -> Draft202012Validator:
    schema = json.loads((_SCHEMAS / f"dataset-v{version}.schema.json").read_text("utf-8"))
    return Draft202012Validator(schema)


def test_a_format_2_case_carries_its_regression_pair(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, PAIR_CASE, STRING_CASE)

    loaded = read_dataset(path)
    regression, plain = loaded.cases

    assert loaded.format == 2
    assert regression.pair == RegressionPair(
        observed="I cannot help with passwords.",
        accepted="Open Settings and request a reset link.",
    )
    assert plain.pair is None
    assert loaded.holds_regressions


def test_a_format_1_dataset_is_still_read_as_holding_no_pair(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", {**HEADER, "guardana_dataset": 1}, STRING_CASE)

    loaded = read_dataset(path)

    assert loaded.format == 1
    assert [case.pair for case in loaded.cases] == [None]
    assert not loaded.holds_regressions


def test_a_format_1_case_with_a_pair_is_refused_as_an_unknown_key(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", {**HEADER, "guardana_dataset": 1}, PAIR_CASE)

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "accepted, observed" in message


@pytest.mark.parametrize(
    ("present", "missing"), [("observed", "accepted"), ("accepted", "observed")]
)
def test_half_a_pair_is_refused_naming_the_missing_half(
    tmp_path: Path, present: str, missing: str
) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, present: "a reply"})

    message = _refusal(path)

    assert f"{path}:2" in message
    assert f"`{present}` without `{missing}`" in message


def test_a_pair_that_is_not_text_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**PAIR_CASE, "observed": ["no"]})

    assert "must be strings" in _refusal(path)


def test_a_pair_in_a_fixture_dataset_is_refused_rather_than_never_regraded(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path / "fixture.jsonl", HEADER, {**PAIR_CASE, "reply": "Open Settings."})

    message = _refusal(path, fixture=True)

    assert f"{path}:2" in message
    assert "fixture dataset" in message


def test_a_regression_tag_alone_does_not_make_a_regression_dataset(tmp_path: Path) -> None:
    path = _write(tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, "tags": ["regression"]})

    assert not read_dataset(path).holds_regressions


@pytest.mark.parametrize(
    "case",
    [
        DatasetCase(
            line=2,
            input=(
                ChatMessage(role="system", content="You answer support questions."),
                ChatMessage(role="user", content="Wo ist meine Rechnung? ✓"),
            ),
            expect={"contains_any": ["invoice"]},
            tags=("regression", "origin:run-1"),
            pair=RegressionPair(observed="", accepted="Your invoice is under Billing."),
        ),
        DatasetCase(line=2, input="Hi", expect={}, tags=(), reply="Hello."),
    ],
)
def test_a_rendered_case_reads_back_field_for_field(tmp_path: Path, case: DatasetCase) -> None:
    path = tmp_path / "golden.jsonl"
    path.write_text(
        f"{render_header('support-golden', '2026.10')}\n{render_case(case)}\n", encoding="utf-8"
    )

    loaded = read_dataset(path, fixture=case.reply is not None)

    assert (loaded.name, loaded.version, loaded.format) == ("support-golden", "2026.10", 2)
    assert loaded.cases == (case,)


def test_every_line_this_build_writes_satisfies_the_format_2_schema() -> None:
    case = DatasetCase(
        line=2,
        input="How do I reset my password?",
        expect={"contains_any": ["reset link"]},
        tags=("regression",),
        pair=RegressionPair(observed="No.", accepted="Request a reset link."),
    )
    validator = _validator(2)

    validator.validate(json.loads(render_header("support-golden", "2026.10")))
    validator.validate(json.loads(render_case(case)))


def test_the_format_2_schema_refuses_half_a_pair_and_the_format_1_schema_any_pair() -> None:
    half = {key: value for key, value in PAIR_CASE.items() if key != "accepted"}

    assert not _validator(2).is_valid(half)
    assert _validator(2).is_valid(PAIR_CASE)
    assert not _validator(1).is_valid(PAIR_CASE)
    assert _validator(1).is_valid({**HEADER, "guardana_dataset": 1})
    assert not _validator(1).is_valid(HEADER)


def test_a_tag_in_the_reserved_namespace_is_refused_by_the_schema_too() -> None:
    assert not _validator(2).is_valid({**STRING_CASE, "tags": ["sample:7"]})
    assert not _validator(2).is_valid({**STRING_CASE, "tags": ["declined:content_filter"]})


def test_a_tag_in_the_reserved_declined_namespace_is_refused(tmp_path: Path) -> None:
    """A case tagged as a decline would be left out of judge-error correction."""
    path = _write(
        tmp_path / "golden.jsonl", HEADER, {**STRING_CASE, "tags": ["declined:content_filter"]}
    )

    message = _refusal(path)

    assert f"{path}:2" in message
    assert "declined:" in message
