"""No string anywhere in a result carries a credential past the renderer seam.

The fixture is a result with every channel occupied, and a distinct fake key is
planted in every string field it holds, found by walking the dataclasses rather
than by naming fields. A field added later is planted without anyone listing it,
so a redactor that names the fields it cleans fails here the day it misses one.

Identifiers are not planted: a rule id, a framework reference and an evaluator id
name engine objects, and the redactor leaves them alone on purpose.
"""

import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from enum import Enum

import pytest
from _documents import scan_result
from guardana.core.redaction import (
    _IDENTIFIER_FIELDS,
    EvidenceMode,
    EvidenceRedactor,
    RedactionPolicy,
)
from guardana.core.report import ScanResult
from guardana.core.reporter import HttpReporter
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.testing import fake_llm_key
from guardana.report import JsonRenderer, get_renderer

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_REDACTED = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))
_KEY_STEM = fake_llm_key()[:-6]


class _Planter:
    """Appends a distinct fake key to every string inside a record, remembering where."""

    def __init__(self) -> None:
        self.planted: dict[str, str] = {}

    def record(self, record: object, path: str) -> object:
        if not is_dataclass(record) or isinstance(record, type | TaxonomyRef):
            return record
        changes = {
            spec.name: self.value(getattr(record, spec.name), f"{path}.{spec.name}")
            for spec in fields(record)
            if spec.init and spec.name not in _IDENTIFIER_FIELDS
        }
        return replace(record, **changes)

    def value(self, value: object, path: str) -> object:
        if isinstance(value, Enum):
            return value
        if isinstance(value, str):
            secret = f"{_KEY_STEM}{len(self.planted):06d}"
            self.planted[path] = secret
            # The original text stays in front so a field that must keep a known value,
            # such as a verdict's outcome, is still recognisable to whatever reads it.
            return f"{value} {secret}"
        if isinstance(value, tuple):
            return tuple(self.value(item, f"{path}[{n}]") for n, item in enumerate(value))
        if isinstance(value, Mapping):
            return {key: self.value(item, f"{path}[{key}]") for key, item in value.items()}
        return self.record(value, path)


def _planted() -> tuple[ScanResult, dict[str, str]]:
    planter = _Planter()
    planted = planter.record(scan_result(), "result")
    if not isinstance(planted, ScanResult):
        raise TypeError("planting changed the type of the result")
    return planted, planter.planted


def _leaked(text: str, planted: Mapping[str, str]) -> list[str]:
    # Whitespace and box drawing are removed so a key a renderer wrapped is still found.
    flat = "".join(_ANSI.sub("", text).replace("│", "").split())
    return sorted(path for path, secret in planted.items() if secret in flat)


def test_every_channel_of_the_fixture_is_planted() -> None:
    _, planted = _planted()

    channels = {path.split(".")[1].split("[")[0] for path in planted}

    assert {
        "findings",
        "unverified",
        "waived",
        "errors",
        "observations",
        "assessments",
        "coverage_shortfall",
        "suites",
    } <= channels


def test_the_planted_keys_reach_an_unredacted_rendering() -> None:
    """Without the seam the keys come out, so their absence below is the seam's doing."""
    result, planted = _planted()

    leaked = _leaked(JsonRenderer(None).render(result), planted)

    for field in (
        "result.findings[0].title",
        "result.findings[0].target_ref",
        "result.findings[0].verdict.rationale",
        "result.assessments[0].rationale",
        "result.observations[0].name",
        "result.observations[0].ref",
    ):
        assert field in leaked


@pytest.mark.parametrize("name", ["json", "sarif", "junit", "human"])
def test_no_string_field_carries_a_key_through_a_renderer(name: str) -> None:
    result, planted = _planted()

    rendered = get_renderer(name, redactor=_REDACTED).render(result)

    assert _leaked(rendered, planted) == []


def test_no_string_field_carries_a_key_to_the_collector() -> None:
    result, planted = _planted()
    sent: list[bytes] = []
    reporter = HttpReporter(
        "http://collector", transport=lambda _url, body: sent.append(body), redactor=_REDACTED
    )

    reporter.submit(result, source="test")

    assert _leaked(sent[0].decode("utf-8"), planted) == []


def test_no_string_field_survives_the_redactor_itself() -> None:
    result, planted = _planted()

    redacted = _REDACTED.redact_result(result)

    assert _leaked(repr(redacted), planted) == []
