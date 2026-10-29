"""A rule skipped for missing coverage leaves a trace in every format, not only in two.

A skip the policy accepts does not refuse the run, so SARIF and JUnit used to carry
nothing about it: `executionSuccessful: true` and a suite counting only the rules that
ran, which a reader takes for every check having happened. A skip that is only about
another system (`not_applicable`) is no coverage gap and changes neither document.
"""

import json
from dataclasses import replace
from typing import Any
from xml.etree.ElementTree import Element, fromstring

import pytest
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report import Evidence, Finding, ScanResult, SkippedRule, SkipReason
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.testing import manifest_for
from guardana.report import get_renderer

_CAPABILITY = SkippedRule(
    "guardana.trace.cross_tenant_retrieval",
    SkipReason.MISSING_CAPABILITY,
    ("read_retrieval",),
    "the trace records no retrieval",
)
_NOT_OFFERED = SkippedRule(
    "guardana.mcp.task_identity",
    SkipReason.NOT_OFFERED,
    ("tasks/get",),
    "the server answers tasks/get as a method it does not offer",
)
_ELSEWHERE = SkippedRule(
    "acme.contract.checkout",
    SkipReason.NOT_APPLICABLE,
    (),
    "the contract is about checkout-agent, not support-agent",
)
_LEAD = Finding("acme.lead", Severity.HIGH, "a lead", (), "src/app.py", Evidence(summary="a lead"))
_GAPS = ScanResult((_LEAD,), ("acme.lead",), (_CAPABILITY, _NOT_OFFERED))
_NO_SKIPS = ScanResult((_LEAD,), ("acme.lead",), ())


def _invocation(result: ScanResult) -> dict[str, Any]:
    doc = json.loads(get_renderer("sarif", run=manifest_for(result)).render(result))
    invocation: dict[str, Any] = doc["runs"][0]["invocations"][0]
    return invocation


def _junit(result: ScanResult) -> Element:
    return fromstring(get_renderer("junit", run=manifest_for(result)).render(result))  # noqa: S314 — our own output


def test_sarif_names_each_coverage_gap_skip_in_a_note() -> None:
    invocation = _invocation(_GAPS)

    notes = invocation["toolExecutionNotifications"]
    assert [n["properties"]["ruleId"] for n in notes] == [
        "guardana.trace.cross_tenant_retrieval",
        "guardana.mcp.task_identity",
    ]
    assert {n["level"] for n in notes} == {"note"}
    assert all("associatedRule" not in n for n in notes)
    assert [n["descriptor"]["id"] for n in notes] == [
        "guardana.skipped.missing_capability",
        "guardana.skipped.not_offered",
    ]
    assert "the trace records no retrieval" in notes[0]["message"]["text"]
    assert "does not offer" in notes[1]["message"]["text"]


def test_a_skip_note_leaves_execution_successful_as_the_gate_left_it() -> None:
    assert _invocation(_GAPS)["executionSuccessful"] is True


def test_junit_writes_a_skipped_testcase_per_coverage_gap_skip() -> None:
    suite = _junit(_GAPS)

    skipped = {
        case.get("name"): case.find("skipped")
        for case in suite.iter("testcase")
        if case.find("skipped") is not None
    }
    assert set(skipped) == {"guardana.trace.cross_tenant_retrieval", "guardana.mcp.task_identity"}
    capability = skipped["guardana.trace.cross_tenant_retrieval"]
    if capability is None:
        raise AssertionError("the capability skip has no <skipped> element")
    assert capability.get("message") == "the trace records no retrieval"
    assert "missing_capability" in (capability.text or "")


def test_junit_counts_add_up_with_the_skips_in_them() -> None:
    suite = _junit(_GAPS)

    testcases = list(suite.iter("testcase"))
    assert suite.get("tests") == str(len(testcases)) == "3"
    assert suite.get("skipped") == "2"
    assert suite.get("failures") == "1"
    assert suite.get("errors") == "0"


@pytest.mark.parametrize("name", ["sarif", "junit"])
def test_a_skip_about_another_system_changes_nothing(name: str) -> None:
    elsewhere = replace(_NO_SKIPS, rules_skipped=(_ELSEWHERE,))

    assert get_renderer(name).render(elsewhere) == get_renderer(name).render(_NO_SKIPS)


def _summary(result: ScanResult, kind: TargetKind | None) -> str:
    run = None if kind is None else manifest_for(result, target_kind=kind)
    return get_renderer("human", run=run).render(result).splitlines()[-1]


def test_a_file_scan_that_observed_nothing_says_so() -> None:
    empty = ScanResult((), ("acme.check",), ())

    assert _summary(empty, TargetKind.ARTIFACT).endswith(" 0 component(s) observed.")


def test_a_file_scan_states_the_components_it_observed() -> None:
    seen = Observation(ObservationKind.MODEL, "model.pkl", "model.pkl")
    result = ScanResult((), ("acme.check",), (), observations=(seen,))

    assert _summary(result, TargetKind.ARTIFACT).endswith(" 1 component(s) observed.")


@pytest.mark.parametrize("kind", [TargetKind.ENDPOINT, TargetKind.TRACE, None])
def test_other_runs_name_components_only_when_they_observed_some(
    kind: TargetKind | None,
) -> None:
    empty = ScanResult((), ("acme.check",), ())

    assert "component(s) observed" not in _summary(empty, kind)
