"""The redactor's span walk: every str redacted by span, identifiers kept, anything unknown refused.

The walk is what a reporter's manifest goes through, so a container it does not know
must raise rather than pass through unredacted.
"""

from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from enum import Enum, StrEnum
from pathlib import Path, PurePosixPath
from typing import NamedTuple

import pytest
from _documents import run_manifest, scan_result
from guardana.core.manifest import RunManifest
from guardana.core.manifest.records import EvaluatorRecord, RuleRecord
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report.finding import Evidence
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.testing import fake_aws_key
from guardana.core.verify import Verifier

_KEY = fake_aws_key()


class _Colour(Enum):
    RED = "red"


class _Name(StrEnum):
    KEY = "AKIA" + "STRENUMVALUE0001"


@dataclass(frozen=True)
class _Holder:
    texts: tuple[str, ...]
    items: list[str]
    unique: set[str]
    frozen: frozenset[str]
    named: dict[str, str]
    derived: str = field(init=False, default="")


class _Pair(NamedTuple):
    left: str
    right: str


class _Bag:
    def __init__(self, text: str) -> None:
        self.text = text


def test_every_container_the_walk_knows_has_its_text_redacted_and_keeps_its_type() -> None:
    holder = _Holder(
        texts=(f"t {_KEY}",),
        items=[f"l {_KEY}"],
        unique={f"s {_KEY}"},
        frozen=frozenset({f"f {_KEY}"}),
        named={f"key {_KEY}": f"v {_KEY}"},
    )

    walked = EvidenceRedactor().redact_spans_in(holder)

    assert _KEY not in repr((walked.texts, walked.items, walked.unique, walked.frozen))
    assert _KEY not in repr(list(walked.named.values()))
    assert list(walked.named) == [f"key {_KEY}"], "a mapping key is never rewritten"
    assert type(walked.items) is list
    assert type(walked.unique) is set
    assert type(walked.frozen) is frozenset


@pytest.mark.parametrize(
    "scalar",
    [
        _Colour.RED,
        _Name.KEY,
        7,
        2.5,
        True,
        None,
        datetime(2026, 1, 2, tzinfo=UTC),
        date(2026, 1, 2),
    ],
    ids=lambda value: type(value).__name__,
)
def test_a_scalar_is_returned_as_it_is(scalar: object) -> None:
    assert EvidenceRedactor().redact_spans_in((scalar,))[0] is scalar


@pytest.mark.parametrize(
    "unknown",
    [
        deque([f"q {_KEY}"]),
        _Pair(f"p {_KEY}", "b"),
        _Bag(f"b {_KEY}"),
        object(),
        RunManifest,
        Path("keys") / f"{_KEY}.txt",
        PurePosixPath(f"keys/{_KEY}"),
        f"b {_KEY}".encode(),
        bytearray(f"b {_KEY}".encode()),
    ],
    ids=[
        "deque",
        "namedtuple",
        "plain-object",
        "object",
        "a-class",
        "path",
        "pure-path",
        "bytes",
        "bytearray",
    ],
)
def test_a_value_the_walk_does_not_know_is_refused(unknown: object) -> None:
    with pytest.raises(TypeError):
        EvidenceRedactor().redact_spans_in({"inside": (unknown,)})


def test_under_metadata_only_text_is_redacted_by_span_never_emptied_or_cut() -> None:
    redactor = EvidenceRedactor(
        RedactionPolicy(mode=EvidenceMode.METADATA_ONLY, max_evidence_bytes=16)
    )
    evidence = Evidence(summary=f"saw {_KEY} " + "word " * 20, detail=f"in {_KEY}")

    walked = redactor.redact_spans_in(evidence)

    assert walked.summary.startswith("saw [redacted:aws-key:")
    assert walked.summary.endswith("word " * 20)
    assert walked.detail.startswith("in [redacted:aws-key:")


def test_identifier_fields_and_records_are_never_rewritten() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(custom_patterns=(r"LLM\d+", r"acme")))
    taxonomy = TaxonomyRef(scheme="OWASP-LLM", id="LLM01", title="Prompt Injection", edition="2025")
    rule = RuleRecord(id=f"acme.{_KEY}", digest="sha256:1", origin=f"acme {_KEY}")
    evaluator = EvaluatorRecord(id=f"acme.{_KEY}", judge=f"acme {_KEY}")
    result = scan_result()

    walked_rule, walked_evaluator, walked_taxonomy = redactor.redact_spans_in(
        (rule, evaluator, taxonomy)
    )
    walked_result = redactor.redact_spans_in(result)

    assert walked_rule.id == rule.id
    assert walked_evaluator.id == evaluator.id
    assert walked_taxonomy is taxonomy
    sent = repr((walked_rule.origin, walked_evaluator.judge))
    assert _KEY not in sent
    assert sent.count("[redacted:aws-key:") == 2
    assert [f.rule_id for f in walked_result.findings] == [f.rule_id for f in result.findings]


def test_a_saved_manifest_walks_without_raising() -> None:
    manifest = run_manifest()

    assert EvidenceRedactor().redact_spans_in(manifest) == manifest


def test_the_manifest_of_a_real_scan_walks_without_raising(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")
    trust = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({f"acme {_KEY}"}))
    verification = Verifier(trust=trust).scan(tmp_path)
    manifest = replace(
        verification.manifest,
        configuration=replace(verification.manifest.configuration, plugins=trust),
    )

    walked = EvidenceRedactor().redact_spans_in(manifest)

    assert walked.rules == manifest.rules
    plugins = walked.configuration.plugins
    assert plugins is not None
    assert len(plugins.allowed) == 1
    assert _KEY not in repr(walked)
