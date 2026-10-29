"""A trace's document digest covers the bytes the reader consumed, and says whether that was all.

The invariant every test here checks: `digest == sha256(file[:bytes])`, so anyone holding
the file can verify it with `head -c <bytes> <file> | sha256sum`. `content` is claimed only
when the reader saw the file end; a ceiling that stopped it first leaves `content_prefix`.
"""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.trace import Dialect, Provenance, TraceLoadError, TraceTruncation, read_trace

_HEADER = {
    "guardana_trace": 3,
    "trace_id": "t-1",
    "producer": {"name": "acme", "version": "1.2"},
    "instrumented": ["messages"],
}


def _native(spans: int) -> list[object]:
    return [
        _HEADER,
        *({"span_id": f"s{n}", "kind": "model_call", "name": "ab"} for n in range(spans)),
    ]


def _otel(spans: int) -> list[object]:
    return [{"name": "ab", "spanId": f"s{n}", "traceId": "tr"} for n in range(spans)]


_DIALECTS: dict[Dialect, Callable[[int], list[object]]] = {
    Dialect.GUARDANA: _native,
    Dialect.OTEL: _otel,
}


def _write(tmp_path: Path, dialect: Dialect, spans: int = 3, name: str = "trace.jsonl") -> Path:
    path = tmp_path / name
    records = _DIALECTS[dialect](spans)
    path.write_bytes(b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in records))
    return path


def _document(path: Path, dialect: Dialect) -> DocumentDigest:
    document = read_trace(path, dialect).trace.provenance.document
    if document is None:
        raise AssertionError(f"{path} read back with no document digest")
    return document


def _covers_its_prefix(path: Path, document: DocumentDigest) -> bool:
    prefix = path.read_bytes()[: document.bytes]
    return document.digest == f"sha256:{hashlib.sha256(prefix).hexdigest()}"


@pytest.mark.parametrize("dialect", list(Dialect))
def test_a_full_read_digests_every_byte_of_the_file(tmp_path: Path, dialect: Dialect) -> None:
    path = _write(tmp_path, dialect)

    document = _document(path, dialect)

    assert document.kind is DigestKind.CONTENT
    assert document.bytes == path.stat().st_size
    assert document.digest == f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


@pytest.mark.parametrize("dialect", list(Dialect))
def test_a_same_size_edit_changes_the_digest(tmp_path: Path, dialect: Dialect) -> None:
    path = _write(tmp_path, dialect)
    before = _document(path, dialect)
    original = path.read_bytes()
    edited = original.replace(b'"ab"', b'"ba"', 1)
    assert len(edited) == len(original)
    assert edited != original
    path.write_bytes(edited)

    after = _document(path, dialect)

    assert after.digest != before.digest
    assert after.bytes == before.bytes
    assert _covers_its_prefix(path, after)


@pytest.mark.parametrize("dialect", list(Dialect))
@pytest.mark.parametrize(
    "edit",
    [
        lambda data: data.replace(b"\n", b"\r\n"),
        lambda data: data.replace(b"\n", b"\n\n", 1),
        lambda data: data.replace(b"\n", b"  \n", 1),
    ],
    ids=["crlf", "blank line", "trailing whitespace"],
)
def test_an_edit_the_parser_cannot_see_still_changes_the_digest(
    tmp_path: Path, dialect: Dialect, edit: Callable[[bytes], bytes]
) -> None:
    path = _write(tmp_path, dialect)
    before = read_trace(path, dialect).trace
    path.write_bytes(edit(path.read_bytes()))

    after = read_trace(path, dialect).trace

    assert after.spans == before.spans, "the edit must be invisible to the parser"
    assert after.provenance.document is not None
    assert before.provenance.document is not None
    assert after.provenance.document.digest != before.provenance.document.digest
    assert after.provenance.document.kind is DigestKind.CONTENT
    assert _covers_its_prefix(path, after.provenance.document)


@pytest.mark.parametrize("dialect", list(Dialect))
def test_a_read_stopped_by_the_byte_ceiling_digests_a_prefix_and_says_so(
    tmp_path: Path, dialect: Dialect, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.trace.load.MAX_TRACE_BYTES", 1_000)
    path = _write(tmp_path, dialect, spans=2_000)

    read = read_trace(path, dialect)
    document = read.trace.provenance.document

    assert read.trace.truncated is TraceTruncation.READ_LIMIT
    assert document is not None
    assert document.kind is DigestKind.CONTENT_PREFIX
    assert 0 < document.bytes < path.stat().st_size
    assert _covers_its_prefix(path, document)


@pytest.mark.parametrize("dialect", list(Dialect))
def test_a_read_stopped_by_the_span_ceiling_digests_a_prefix_and_says_so(
    tmp_path: Path, dialect: Dialect, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.trace.load.MAX_SPANS", 3)
    path = _write(tmp_path, dialect, spans=2_000)

    read = read_trace(path, dialect)
    document = read.trace.provenance.document

    assert read.trace.truncated is TraceTruncation.READ_LIMIT
    assert document is not None
    assert document.kind is DigestKind.CONTENT_PREFIX
    assert 0 < document.bytes < path.stat().st_size
    assert _covers_its_prefix(path, document)


@pytest.mark.parametrize("dialect", list(Dialect))
def test_a_small_file_stopped_by_the_span_ceiling_never_claims_its_whole_content(
    tmp_path: Path, dialect: Dialect, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The whole file fits one buffered read, so every byte is hashed; the reader still
    # stopped before it saw the end, and only that entitles the digest to say `content`.
    monkeypatch.setattr("guardana.core.trace.load.MAX_SPANS", 1)
    path = _write(tmp_path, dialect, spans=3)

    document = _document(path, dialect)

    assert document.kind is DigestKind.CONTENT_PREFIX
    assert _covers_its_prefix(path, document)


@pytest.mark.parametrize("dialect", list(Dialect))
def test_a_file_that_is_not_utf8_is_still_refused(tmp_path: Path, dialect: Dialect) -> None:
    path = tmp_path / "binary.jsonl"
    path.write_bytes(json.dumps(_HEADER).encode("utf-8") + b"\n\xff\xfe{\x00\n")

    with pytest.raises(TraceLoadError, match="not UTF-8"):
        read_trace(path, dialect)


def test_provenance_refuses_a_bare_digest() -> None:
    with pytest.raises(TypeError):
        Provenance(producer="p", source="s", dialect="d", document_digest="sha256:00")  # type: ignore[call-arg]


def test_the_bare_digest_is_still_readable_from_the_document() -> None:
    document = DocumentDigest.of(b"{}\n", DigestKind.CONTENT)
    provenance = Provenance(producer="p", source="s", dialect="d", document=document)

    assert provenance.document_digest == document.digest
    assert Provenance(producer="p", source="s", dialect="d").document_digest is None


@pytest.mark.parametrize(
    ("digest", "size"),
    [("0" * 64, 1), ("md5:" + "0" * 32, 1), ("sha256:" + "0" * 63, 1), ("sha256:" + "0" * 64, -1)],
    ids=["no algorithm", "another algorithm", "short", "negative size"],
)
def test_a_document_digest_no_reader_could_produce_is_refused(digest: str, size: int) -> None:
    with pytest.raises(ValueError, match="document digest"):
        DocumentDigest(digest=digest, kind=DigestKind.CONTENT, bytes=size)
