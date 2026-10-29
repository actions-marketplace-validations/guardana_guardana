"""A quality suite's dataset: one JSONL file of cases, named and versioned by its author.

The first non-blank line is a header naming the dataset; every other non-blank line is
one case.

Format 2 adds a case's optional `observed` and `accepted` replies, both or neither: the
failure a regression case was promoted from and a correct reply a reviewer wrote. A live
run never reads them; `guardana rule test` and a recipe regrade them. A format-1 file is
still read, as a dataset holding no such pair.

This module reads, bounds and renders the file and nothing more. A case's identity and
duplicate detection belong to the suite: identity is computed from the case's *effective*
expectation, and only the suite knows the default its own `expect:` supplies.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from guardana.core.fingerprint import digest_of
from guardana.core.target import ChatMessage
from guardana.core.target.decline import DECLINED_TAG_PREFIX
from guardana.core.trace.limits import MAX_RECORD_BYTES, MAX_TRACE_BYTES

DATASET_FORMAT = 2
"""The header's `guardana_dataset` value this build writes."""

READ_FORMATS = (1, 2)
"""Every `guardana_dataset` value this build reads."""

REGRESSION_TAG = "regression"
"""The tag `case add` writes on a promoted case; a label only, it changes no gate."""

MAX_CASES = 100_000
"""Cases read from one dataset; a file with more is refused, never cut short."""

_FORMAT_KEY = "guardana_dataset"
_HEADER_KEYS = frozenset({_FORMAT_KEY, "name", "version"})
_V1_CASE_KEYS = frozenset({"input", "expect", "tags", "reply"})
_CASE_KEYS = {1: _V1_CASE_KEYS, 2: _V1_CASE_KEYS | {"observed", "accepted"}}
_MESSAGE_KEYS = frozenset({"role", "content"})
_ROLES: tuple[Literal["system", "user", "assistant"], ...] = ("system", "user", "assistant")
_RESERVED_TAG_PREFIX = "sample:"


class DatasetError(ValueError):
    """A dataset path or file that cannot be used, named down to the line at fault."""


@dataclass(frozen=True, slots=True)
class RegressionPair:
    """A regression case's two replies: the failure it records and a correct one.

    The case's expectation holds only while `observed` grades `fail` and `accepted`
    grades `pass`. Neither is ever sent, and neither is part of the case's identity.
    """

    observed: str
    accepted: str


@dataclass(frozen=True, slots=True)
class DatasetCase:
    """One case as its line declares it, before the suite overlays its own defaults.

    `expect` is the case's own expectation exactly as read, empty when the line has
    none. `reply` answers the case without a target and appears only in a fixture
    dataset. `pair` is a regression case's two replies, None on any other case.
    """

    line: int
    input: str | tuple[ChatMessage, ...]
    expect: Mapping[str, object]
    tags: tuple[str, ...]
    reply: str | None = None
    pair: RegressionPair | None = None


@dataclass(frozen=True, slots=True)
class Dataset:
    """A loaded dataset: the author's name and version, the file's digest and its cases.

    `format` is the header's `guardana_dataset` as read; a format-1 file holds no pair.
    """

    name: str
    version: str
    digest: str
    cases: tuple[DatasetCase, ...]
    format: int = DATASET_FORMAT

    @property
    def identity(self) -> str:
        """The dataset as an assessment names it, `name@version`."""
        return f"{self.name}@{self.version}"

    @property
    def holds_regressions(self) -> bool:
        """Whether any case carries an `observed`/`accepted` pair.

        Such a dataset is a regression gate: a suite over it may neither sample nor set
        a bar below 1. A tag never makes one, so a dataset an author tagged by hand keeps
        loading under the bar it already had.
        """
        return any(case.pair is not None for case in self.cases)


def resolve_dataset_path(raw: str, rule_file: Path) -> Path:
    """Resolve a rule's `dataset:` value to a file inside the rule file's directory.

    Guardana sends traffic only to destinations the run names, and a dataset is not
    one, so a URL is refused; and a rule file must not read outside the directory it
    ships in, so an absolute path, a `..` that climbs out and a symbolic link that
    points out are refused too.
    """
    if not raw.strip():
        raise DatasetError(f"{rule_file}: `dataset:` names no file")
    if "://" in raw:
        raise DatasetError(
            f"{rule_file}: dataset {raw!r} is a URL; a dataset is read from a file beside "
            f"the rule, because a run sends traffic only to destinations it names"
        )
    if Path(raw).is_absolute():
        raise DatasetError(
            f"{rule_file}: dataset {raw!r} is an absolute path; name it relative to the "
            f"rule file's directory"
        )
    base = rule_file.parent.resolve()
    lexical = Path(os.path.normpath(base / raw))
    if not lexical.is_relative_to(base):
        raise DatasetError(
            f"{rule_file}: dataset {raw!r} climbs outside the rule file's directory {base}"
        )
    resolved = lexical.resolve()
    if not resolved.is_relative_to(base):
        raise DatasetError(
            f"{rule_file}: dataset {raw!r} is a symbolic link to {resolved}, outside the "
            f"rule file's directory {base}"
        )
    return resolved


def read_dataset(path: Path, *, fixture: bool = False) -> Dataset:
    """Read and validate the dataset at `path`, refusing the whole file on any bad line.

    `fixture` admits a `reply` on each case, which only a rule's fixture dataset may
    carry: a reply in a dataset used against a live target would be a canned answer
    graded in place of the target's. Formats 1 and 2 are read.
    """
    return parse_dataset(read_dataset_text(path), str(path), fixture=fixture)


def read_dataset_text(path: Path) -> str:
    """Read the whole file, bounded, as UTF-8.

    The digest is of the file's bytes: a strict UTF-8 decode round-trips them exactly,
    so hashing the text is hashing the file.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_TRACE_BYTES + 1)
    except OSError as exc:
        raise DatasetError(f"{path} could not be read: {exc}") from exc
    if len(data) > MAX_TRACE_BYTES:
        raise DatasetError(
            f"{path} is over the {MAX_TRACE_BYTES}-byte ceiling; it is refused rather than "
            f"read in part"
        )
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetError(
            f"{path} is not UTF-8 text, so it is not a JSONL dataset: {exc}"
        ) from exc


def parse_dataset(text: str, where: str, *, fixture: bool = False) -> Dataset:
    """Validate a whole dataset's text; `where` names it in every refusal."""
    if len(text.encode("utf-8")) > MAX_TRACE_BYTES:
        raise DatasetError(
            f"{where} is over the {MAX_TRACE_BYTES}-byte ceiling; it is refused rather than "
            f"read in part"
        )
    header: tuple[int, str, str] | None = None
    cases: list[DatasetCase] = []
    for number, raw in enumerate(text.split("\n"), start=1):
        if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
            raise DatasetError(
                f"{where}:{number}: the line is over the {MAX_RECORD_BYTES}-byte ceiling; it is "
                f"refused rather than truncated"
            )
        stripped = raw.strip()
        if not stripped:
            continue
        record = _parse(stripped, where, number)
        if header is None:
            header = _header(record, where, number)
            continue
        if len(cases) >= MAX_CASES:
            raise DatasetError(
                f"{where}:{number}: the dataset has more than {MAX_CASES} cases; split it or "
                f"sample it"
            )
        cases.append(_case(record, header[0], where, number, fixture=fixture))
    if header is None:
        raise DatasetError(
            f"{where} has no header; its first line must be "
            f'{{"{_FORMAT_KEY}": {DATASET_FORMAT}, "name": …, "version": …}}'
        )
    if not cases:
        raise DatasetError(f"{where} has a header and no cases")
    fmt, name, version = header
    return Dataset(
        name=name, version=version, digest=digest_of(text), cases=tuple(cases), format=fmt
    )


def render_header(name: str, version: str) -> str:
    """Render a header line in the format this build writes, without its line ending."""
    return _dump({_FORMAT_KEY: DATASET_FORMAT, "name": name, "version": version})


def render_case(case: DatasetCase) -> str:
    """Render one case as a line `parse_dataset` reads back field for field.

    The line has no line ending and leaves absent optional keys out. A single user
    message is written as a string, which is how `parse_dataset` reads a string.
    """
    record: dict[str, object] = {"input": _input_record(case.input)}
    if case.expect:
        record["expect"] = dict(case.expect)
    if case.tags:
        record["tags"] = list(case.tags)
    if case.reply is not None:
        record["reply"] = case.reply
    if case.pair is not None:
        record["observed"] = case.pair.observed
        record["accepted"] = case.pair.accepted
    return _dump(record)


def _input_record(value: str | tuple[ChatMessage, ...]) -> object:
    if isinstance(value, str):
        return value
    return {"messages": [{"role": m.role, "content": m.content} for m in value]}


def _dump(record: Mapping[str, object]) -> str:
    """Encode one compact JSON line, non-ASCII text kept as written."""
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


class _RepeatedKeyError(ValueError):
    """A JSON object named one key twice."""


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build an object, refusing a repeated key that `json` would silently resolve to the last."""
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise _RepeatedKeyError(key)
        parsed[key] = value
    return parsed


def _parse(raw: str, path: str, number: int) -> dict[str, object]:
    """Parse one line into a JSON object, refusing anything else by its line number."""
    try:
        parsed: object = json.loads(raw, object_pairs_hook=_unique_keys)
    except _RepeatedKeyError as exc:
        raise DatasetError(f"{path}:{number}: the key {exc} appears twice on the line") from exc
    except json.JSONDecodeError as exc:
        raise DatasetError(f"{path}:{number}: the line is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise DatasetError(f"{path}:{number}: the line is not a JSON object")
    return parsed


def _header(record: dict[str, object], path: str, number: int) -> tuple[int, str, str]:
    """Validate the header line and return the dataset's format, name and version."""
    if _FORMAT_KEY not in record:
        raise DatasetError(
            f"{path}:{number}: the dataset does not open with a header; its first line must "
            f'be {{"{_FORMAT_KEY}": {DATASET_FORMAT}, "name": …, "version": …}}'
        )
    # The format is checked before the keys: a later format may add header keys, and
    # its file should be refused as another version, not as a typo.
    fmt = record[_FORMAT_KEY]
    if not isinstance(fmt, int) or isinstance(fmt, bool):
        raise DatasetError(
            f"{path}:{number}: `{_FORMAT_KEY}` must be the integer "
            f"{' or '.join(map(str, READ_FORMATS))}, not {fmt!r}"
        )
    if fmt not in READ_FORMATS:
        raise DatasetError(
            f"{path}:{number}: dataset format {fmt} was written by another Guardana version; "
            f"this build reads formats {' and '.join(map(str, READ_FORMATS))}"
        )
    _refuse_unknown(record, _HEADER_KEYS, "header", path, number)
    return (
        fmt,
        _non_empty(record.get("name"), "the header's `name`", path, number),
        _non_empty(record.get("version"), "the header's `version`", path, number),
    )


def _case(
    record: dict[str, object], fmt: int, path: str, number: int, *, fixture: bool
) -> DatasetCase:
    """Validate one case line of a dataset in format `fmt`."""
    _refuse_unknown(record, _CASE_KEYS[fmt], "case", path, number)
    if "input" not in record:
        raise DatasetError(f"{path}:{number}: the case has no `input`")
    reply = record.get("reply")
    if "reply" in record:
        if not fixture:
            raise DatasetError(
                f"{path}:{number}: `reply` is allowed only in a rule's fixture dataset; a "
                f"dataset run against a target takes its replies from the target"
            )
        if not isinstance(reply, str):
            raise DatasetError(f"{path}:{number}: `reply` must be a string")
    return DatasetCase(
        line=number,
        input=_input(record["input"], path, number),
        expect=_expect(record.get("expect", {}), path, number),
        tags=_tags(record.get("tags", []), path, number),
        reply=reply if isinstance(reply, str) else None,
        pair=_pair(record, path, number, fixture=fixture),
    )


def _pair(
    record: Mapping[str, object], path: str, number: int, *, fixture: bool
) -> RegressionPair | None:
    """Read a regression case's `observed` and `accepted`, which come together or not at all.

    A fixture dataset scripts the replies a suite's samples are graded on; a pair there
    would never be regraded, so it is refused rather than ignored.
    """
    present = [key for key in ("observed", "accepted") if key in record]
    if not present:
        return None
    if fixture:
        raise DatasetError(
            f"{path}:{number}: `{present[0]}` belongs to a regression case in the suite's own "
            f"dataset; a fixture dataset scripts its replies with `reply`"
        )
    if len(present) == 1:
        missing = "accepted" if present[0] == "observed" else "observed"
        raise DatasetError(
            f"{path}:{number}: the case has `{present[0]}` without `{missing}`; a regression "
            f"case carries both the failing reply and a correct one, or neither"
        )
    observed, accepted = record["observed"], record["accepted"]
    if not isinstance(observed, str) or not isinstance(accepted, str):
        raise DatasetError(f"{path}:{number}: `observed` and `accepted` must be strings")
    return RegressionPair(observed=observed, accepted=accepted)


def _input(value: object, path: str, number: int) -> str | tuple[ChatMessage, ...]:
    """Read a case's input: a non-empty prompt, or a message list that ends on the user."""
    if isinstance(value, str):
        return _non_empty(value, "`input`", path, number)
    if not isinstance(value, dict):
        raise DatasetError(
            f'{path}:{number}: `input` must be a non-empty string or {{"messages": [...]}}'
        )
    _refuse_unknown(value, frozenset({"messages"}), "`input`", path, number)
    items = value.get("messages")
    if not isinstance(items, list) or not items:
        raise DatasetError(f"{path}:{number}: `input.messages` must be a non-empty list")
    messages = tuple(_message(item, path, number) for item in items)
    if messages[-1].role != "user":
        raise DatasetError(
            f"{path}:{number}: `input.messages` ends on a {messages[-1].role} message; the "
            f"last message must be from the user, because it is what the target answers"
        )
    return messages


def _message(item: object, path: str, number: int) -> ChatMessage:
    """One `{"role", "content"}` message of a case's input."""
    if not isinstance(item, dict):
        raise DatasetError(f"{path}:{number}: every item of `input.messages` must be an object")
    _refuse_unknown(item, _MESSAGE_KEYS, "message", path, number)
    role = item.get("role")
    for allowed in _ROLES:
        if role == allowed:
            content = _non_empty(item.get("content"), "a message's `content`", path, number)
            return ChatMessage(role=allowed, content=content)
    raise DatasetError(f"{path}:{number}: message role {role!r} is not one of {', '.join(_ROLES)}")


def _expect(value: object, path: str, number: int) -> Mapping[str, object]:
    """Return a case's own expectation, read-only and otherwise as written."""
    if not isinstance(value, dict):
        raise DatasetError(f"{path}:{number}: `expect` must be an object")
    return MappingProxyType(dict(value))


def _tags(value: object, path: str, number: int) -> tuple[str, ...]:
    """Read a case's tags: non-empty strings outside the prefixes the suite reserves."""
    if not isinstance(value, list):
        raise DatasetError(f"{path}:{number}: `tags` must be a list of strings")
    tags = tuple(_non_empty(tag, "a tag", path, number) for tag in value)
    for tag in tags:
        if tag.startswith(_RESERVED_TAG_PREFIX):
            raise DatasetError(
                f"{path}:{number}: tag {tag!r} uses the `{_RESERVED_TAG_PREFIX}` prefix, which "
                f"the suite reserves for marking a sampled run"
            )
        if tag.startswith(DECLINED_TAG_PREFIX):
            raise DatasetError(
                f"{path}:{number}: tag {tag!r} uses the `{DECLINED_TAG_PREFIX}` prefix, which "
                f"marks a case graded from a declined request and is kept out of judge-error "
                f"correction"
            )
    return tags


def _non_empty(value: object, what: str, path: str, number: int) -> str:
    """Return `value` if it is a string with content, refusing it otherwise."""
    if not isinstance(value, str) or not value.strip():
        raise DatasetError(f"{path}:{number}: {what} must be a non-empty string")
    return value


def _refuse_unknown(
    record: Mapping[str, object], allowed: frozenset[str], what: str, path: str, number: int
) -> None:
    """Refuse any key outside `allowed`, naming them all at once."""
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise DatasetError(
            f"{path}:{number}: unknown {what} key(s) {', '.join(unknown)}; expected only "
            f"{', '.join(sorted(allowed))}"
        )
