"""An output sees no more than the saved run holds; one that sends, every text redacted again.

One fake credential is planted in every channel of a result, in the target ref, in the
stop and judge messages and in a kept exchange. A discovered recording format and a
discovered recording reporter are then run, and what each was handed is read where it
arrived: inside the output's own module. A second credential is planted in every str of
a manifest by a walk that refuses any type it does not know, and only the rule and
evaluator ids may carry it to a reporter.
"""

import sys
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import fields, is_dataclass, replace
from datetime import datetime
from enum import Enum
from functools import reduce
from pathlib import Path
from typing import Any, ClassVar, Protocol

import pytest
from _documents import run_manifest, scan_result
from _fake_distribution import FakeSite
from _output_modules import RECORDING_RENDERER, RECORDING_REPORTER, body
from guardana.core.entrypoints import RENDERER_GROUP, REPORTER_GROUP
from guardana.core.gate import GateOutcome
from guardana.core.manifest import RunManifest
from guardana.core.manifest.usage import JudgeUsage
from guardana.core.output import (
    BoundaryError,
    DeliveryStatus,
    deliver,
    outbound,
    render,
    select_renderer,
    select_reporter,
)
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.recording import RecordedExchange, Recording
from guardana.core.redaction import EvidenceRedactor
from guardana.core.report import ScanResult
from guardana.core.report.finding import Finding
from guardana.core.target import ChatMessage
from guardana.core.verify import Verification

_PLANTED = "AKIA" + "PLANTED0FAKE0KEY"
"""A fake credential in the shape of an access key id, built in code, valid nowhere."""

_REF = f"https://model.invalid/v1?key={_PLANTED}"
_TRUST = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-guardana-outputs"}))

_NOT_TEXT = frozenset({"rules_run", "stopped_by", "usage", "protocols", "trials_per_case"})
"""Channels holding only rule ids, counts or protocol versions, so nothing can be planted."""


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _planted_finding(finding: Finding) -> Finding:
    verdict = finding.verdict
    return replace(
        finding,
        title=f"title {_PLANTED}",
        target_ref=f"ref {_PLANTED}",
        evidence=replace(finding.evidence, summary=f"saw {_PLANTED}", detail=f"in {_PLANTED}"),
        verdict=None if verdict is None else replace(verdict, rationale=f"why {_PLANTED}"),
    )


def _planted_result() -> ScanResult:
    base = scan_result()
    scope = base.scope
    return replace(
        base,
        findings=tuple(_planted_finding(f) for f in base.findings),
        unverified=tuple(_planted_finding(f) for f in base.unverified),
        waived=tuple(_planted_finding(f) for f in base.waived),
        errors=tuple(replace(e, reason=f"failed {_PLANTED}") for e in base.errors),
        rules_skipped=tuple(replace(s, detail=f"skipped {_PLANTED}") for s in base.rules_skipped),
        observations=tuple(
            replace(o, ref=f"obs {_PLANTED}", attributes={"seen": _PLANTED})
            for o in base.observations
        ),
        coverage_shortfall=tuple(
            replace(g, detail=f"short {_PLANTED}") for g in base.coverage_shortfall
        ),
        assessments=tuple(replace(a, rationale=f"case {_PLANTED}") for a in base.assessments),
        suites={key: replace(s, reason=f"suite {_PLANTED}") for key, s in base.suites.items()},
        scope=None if scope is None else replace(scope, files=(f"keys/{_PLANTED}.txt",)),
    )


def _kept_exchanges() -> Recording:
    return Recording(
        name="guardana-probe",
        version="run",
        verbatim=False,
        subject=None,
        origin=None,
        exchanges=(
            RecordedExchange(
                rule="guardana.prompt.jailbreak",
                input=(ChatMessage(role="user", content=f"use {_PLANTED}"),),
                reply=f"here is {_PLANTED}",
                meta={"session": _PLANTED, "model": "m"},
            ),
        ),
        digest=None,
    )


def _planted() -> Verification:
    manifest = run_manifest()
    return Verification(
        result=_planted_result(),
        manifest=replace(manifest, target=replace(manifest.target, ref=_REF)),
        gate=GateOutcome.FAIL,
        judge_usage={"judge": JudgeUsage(requests=2, input_tokens=10, output_tokens=5)},
        judge_stops=(f"judge stopped {_PLANTED}",),
        exchanges=_kept_exchanges(),
        stop_messages=(f"the target stopped {_PLANTED}",),
    )


def test_the_credential_is_planted_in_every_channel_that_carries_text() -> None:
    """Fails when a channel is added to `ScanResult` and nothing is planted in it here."""
    result = _planted_result()

    planted = {f.name for f in fields(ScanResult) if _PLANTED in repr(getattr(result, f.name))}

    assert planted == {f.name for f in fields(ScanResult)} - _NOT_TEXT


def _seen(module_name: str) -> Verification:
    (seen,) = sys.modules[module_name].SEEN
    assert isinstance(seen, Verification)
    return seen


def test_a_discovered_format_sees_no_planted_credential(site: FakeSite) -> None:
    module = site.module(body(RECORDING_RENDERER, "acme-table"))
    site.distribution("acme-guardana-outputs", (RENDERER_GROUP, "acme-table", module.name))

    render(select_renderer("acme-table", _TRUST), _planted())

    seen = _seen(module.name)
    assert seen.manifest.target.ref == _REF, "a format is handed the target ref as saved"
    without_ref = replace(
        seen, manifest=replace(seen.manifest, target=replace(seen.manifest.target, ref=""))
    )
    assert _PLANTED not in repr(without_ref)
    assert seen.stop_messages == ()
    assert seen.judge_stops == ()
    assert seen.exchanges is not None
    (exchange,) = seen.exchanges.exchanges
    assert exchange.altered
    assert dict(exchange.meta) == {"model": "m"}


def test_a_discovered_reporter_sees_no_planted_credential(site: FakeSite) -> None:
    module = site.module(body(RECORDING_REPORTER, "acme-webhook"))
    site.distribution("acme-guardana-outputs", (REPORTER_GROUP, "acme-webhook", module.name))

    delivery = deliver(select_reporter("acme-webhook", "x", _TRUST), _planted())

    assert delivery.status is DeliveryStatus.DELIVERED
    seen = _seen(module.name)
    assert _PLANTED not in repr(seen)
    assert seen.manifest.target.ref.startswith("https://model.invalid/v1?key=")
    assert seen.exchanges is None
    assert seen.stop_messages == ()
    assert seen.judge_stops == ()


def test_the_boundary_redacts_the_result_as_the_built_ins_do_and_keeps_the_verdict() -> None:
    given = _planted()

    for leaves_machine in (False, True):
        seen = outbound(given, leaves_machine=leaves_machine)

        assert seen.result == EvidenceRedactor().redact_result(given.result)
        assert seen.gate is given.gate
        assert seen.exit_code == given.exit_code
        assert seen.open_questions == given.open_questions
        assert seen.judge_usage == given.judge_usage
        assert replace(seen.manifest, target=given.manifest.target) == given.manifest


def test_a_target_ref_that_leaves_the_machine_is_redacted_at_redacted_mode() -> None:
    manifest = run_manifest()
    given = Verification(
        result=scan_result(),
        manifest=replace(
            manifest, target=replace(manifest.target, ref="https://owner@example.invalid/v1")
        ),
        gate=GateOutcome.PASS,
    )

    kept = outbound(given, leaves_machine=False).manifest.target.ref
    sent = outbound(given, leaves_machine=True).manifest.target.ref

    assert kept == "https://owner@example.invalid/v1"
    assert "owner@example.invalid" not in sent
    assert sent.startswith("https://")


_KEY = "sk-" + "PLANTED0FAKE0KEY0123"
"""A fake credential in the shape of an API key, built in code, valid nowhere."""

_SHAPED = frozenset(
    {
        ("DocumentDigest", "digest"),
        ("ExchangesRecord", "digest"),
        ("FixturesRecord", "digest"),
        ("RecipeRecord", "digest"),
        ("RecipeRecord", "lock_digest"),
    }
)
"""Fields the manifest refuses to hold anything but a fixed shape, so nothing can be planted."""

_IDENTIFIERS = frozenset(
    {
        ("RuleRecord", "id"),
        ("EvaluatorRecord", "id"),
        ("SkippedRule", "rule_id"),
        ("ResultSummary", "rules_run"),
        ("CalibrationRecord", "assessor"),
        ("JudgeCorrection", "assessor"),
        ("SuiteCorrection", "assessor"),
    }
)
"""Fields naming a rule or an assessor, which the boundary keeps as they are."""

_KEYS = frozenset(
    {
        ("ToolInfo", "distribution_versions key"),
        ("CoverageRecord", "protocols key"),
        ("RunUsage", "judge key"),
    }
)
"""Mapping keys, which name a distribution, a protocol or a judge and are never rewritten."""

_UNCHANGED = (Enum, bool, int, float, datetime, type(None))
"""Values this test leaves alone: none of them can hold a credential."""

_Leaf = tuple[str, str, str]
"""Where a str sits: the owning dataclass's name, its field and the str itself."""


def _plant(value: object) -> object:
    """Append `_KEY` to every str in a manifest; raise on a type this test does not know.

    Mapping keys are not planted: they are pinned in `_KEYS`, and the boundary keeps them.
    """
    if isinstance(value, _UNCHANGED):
        return value
    if isinstance(value, str):
        return f"{value} {_KEY}"
    if isinstance(value, tuple | frozenset) and type(value) in (tuple, frozenset):
        return type(value)(_plant(item) for item in value)
    if isinstance(value, dict) and type(value) is dict:
        return {key: _plant(item) for key, item in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return _plant_record(value)
    raise TypeError(
        f"the manifest holds a {type(value).__qualname__}, which this test cannot plant"
    )


class _Dataclass(Protocol):
    __dataclass_fields__: ClassVar[dict[str, Any]]


def _plant_record(record: _Dataclass) -> object:
    planted = record
    for spec in fields(record):
        if not spec.init:
            continue
        try:
            planted = replace(planted, **{spec.name: _plant(getattr(record, spec.name))})
        except ValueError:
            if (type(record).__name__, spec.name) not in _SHAPED:
                raise
    return planted


def _strs(value: object, owner: tuple[str, str] = ("", "")) -> Iterator[_Leaf]:
    """Yield every str reachable from `value`, whatever holds it, mapping keys included."""
    if isinstance(value, str):
        yield (*owner, value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _strs(key, (owner[0], f"{owner[1]} key"))
            yield from _strs(item, owner)
    elif is_dataclass(value) and not isinstance(value, type):
        for spec in fields(value):
            yield from _strs(getattr(value, spec.name), (type(value).__name__, spec.name))
    elif isinstance(value, Iterable) and not isinstance(value, bytes):
        for item in value:
            yield from _strs(item, owner)


def _planted_manifest() -> RunManifest:
    planted = _plant(run_manifest())
    if not isinstance(planted, RunManifest):
        raise TypeError(type(planted).__name__)
    return planted


def test_the_key_is_planted_in_every_text_field_of_the_manifest() -> None:
    """Fails when the manifest gains a str this test does not plant."""
    planted = _planted_manifest()
    unplanted = {
        (owner, name)
        for owner, name, text in _strs(planted)
        if not isinstance(text, Enum) and _KEY not in text
    }

    assert unplanted == _SHAPED | _KEYS
    plugins = planted.configuration.plugins
    assert plugins is not None
    assert any(_KEY in name for name in plugins.allowed)
    assert repr(planted).count(_KEY) > len(fields(RunManifest))


def test_a_reporter_gets_every_text_field_of_the_manifest_redacted_again() -> None:
    planted = _planted_manifest()
    given = Verification(result=scan_result(), manifest=planted, gate=GateOutcome.FAIL)

    sent = outbound(given, leaves_machine=True).manifest
    kept = outbound(given, leaves_machine=False).manifest

    leaked = {(o, n) for o, n, text in _strs(sent) if _KEY in text}
    assert leaked == _IDENTIFIERS
    identifiers = {text for o, n, text in _strs(planted) if (o, n) in _IDENTIFIERS}
    assert _KEY not in reduce(lambda shown, text: shown.replace(text, ""), identifiers, repr(sent))
    assert sent.configuration.plugins is not None
    assert sent.configuration.plugins.allowed
    assert kept == planted, "a format gets the manifest as saved"


def test_a_reporter_gets_rule_and_evaluator_ids_unchanged_whatever_they_hold() -> None:
    saved = run_manifest()
    planted = replace(
        saved,
        rules=tuple(replace(r, id=f"acme.{_KEY}") for r in saved.rules),
        evaluators=tuple(replace(e, id=f"acme.{_KEY}") for e in saved.evaluators),
    )
    given = Verification(result=scan_result(), manifest=planted, gate=GateOutcome.FAIL)

    sent = outbound(given, leaves_machine=True).manifest

    assert [r.id for r in sent.rules] == [r.id for r in planted.rules]
    assert [e.id for e in sent.evaluators] == [e.id for e in planted.evaluators]
    assert sent.rules


class _Bag:
    """A container the boundary does not know."""

    def __init__(self, *items: str) -> None:
        self.items = items


def test_a_manifest_holding_a_container_the_boundary_does_not_know_is_never_sent(
    site: FakeSite,
) -> None:
    module = site.module(body(RECORDING_REPORTER, "acme-webhook"))
    site.distribution("acme-guardana-outputs", (REPORTER_GROUP, "acme-webhook", module.name))
    saved = run_manifest()
    odd = replace(saved, target=replace(saved.target, capabilities=_Bag(f"chat {_KEY}")))  # type: ignore[arg-type]
    given = Verification(result=scan_result(), manifest=odd, gate=GateOutcome.FAIL)

    with pytest.raises(TypeError):
        outbound(given, leaves_machine=True)
    with pytest.raises(BoundaryError) as refused:
        deliver(select_reporter("acme-webhook", "x", _TRUST), given)

    assert refused.value.reason == "TypeError"
    assert sys.modules[module.name].SEEN == []


def test_a_manifest_holding_nothing_to_redact_reaches_a_reporter_unchanged() -> None:
    saved = run_manifest()
    given = Verification(result=scan_result(), manifest=saved, gate=GateOutcome.FAIL)

    sent = outbound(given, leaves_machine=True).manifest

    assert sent == saved
