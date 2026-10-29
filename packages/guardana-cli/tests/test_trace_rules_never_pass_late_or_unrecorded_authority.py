"""Trace rules never pass over authority recorded too late, a channel not recorded, or a
comparison the trace cannot make."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_CONSENT = "guardana.trace.consent_scope_exceeded"
_APPROVAL = "guardana.trace.unapproved_side_effect"
_POLICY = "guardana.trace.policy_decision_ignored"
_IDENTITY = "guardana.trace.identity_disagreement"
_PASSTHROUGH = "guardana.trace.credential_passthrough"


@dataclass(frozen=True)
class _Run:
    exit_code: int
    rules_run: list[str]
    findings: list[str]
    unverified: list[str]

    def answered(self, rule_id: str) -> bool:
        """Whether the rule said anything other than a silent pass."""
        return rule_id in self.findings or rule_id in self.unverified


def _analyze(tmp_path: Path, instrumented: list[str], *spans: dict[str, Any]) -> _Run:
    header = {
        "guardana_trace": 3,
        "trace_id": "t-1",
        "producer": {"name": "acme-harness", "version": "1"},
        "instrumented": instrumented,
        "terminated": True,
    }
    footer = {"guardana_trace_end": 3, "spans": len(spans)}
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        "".join(json.dumps(line) + "\n" for line in (header, *spans, footer)), encoding="utf-8"
    )
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app, ["analyze-trace", str(trace), "--format", "json", "--output", str(saved)]
    )
    document = json.loads(saved.read_text(encoding="utf-8"))
    return _Run(
        exit_code=result.exit_code,
        rules_run=document["run"]["result_summary"]["rules_run"],
        findings=[finding["rule_id"] for finding in document["findings"]],
        unverified=[finding["rule_id"] for finding in document["unverified"]],
    )


def _use(scopes: list[str]) -> dict[str, Any]:
    return {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "docs",
        "delegations": [{"actor": "client-1", "boundary": "client->docs", "scopes": scopes}],
    }


def _grant(span_id: str, scopes: list[str]) -> dict[str, Any]:
    return {
        "span_id": span_id,
        "kind": "tool_execution",
        "name": "consent",
        "consents": [{"client": "client-1", "granted": True, "scopes": scopes}],
    }


def _charge() -> dict[str, Any]:
    return {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "charge_card",
        "effects": [{"sink": "payment", "action": "charge_card", "status": "executed"}],
    }


def _approval(outcome: str) -> dict[str, Any]:
    return {
        "span_id": "s2",
        "kind": "tool_execution",
        "name": "approval",
        "approvals": [{"action": "charge_card", "outcome": outcome}],
    }


def _presented(audience: list[str], kind: str | None = "bearer") -> dict[str, Any]:
    credential: dict[str, Any] = {"digest": "sha256:token"}
    if kind is not None:
        credential["kind"] = kind
    if audience:
        credential["audience"] = audience
    return {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "fetch_report",
        "identity": {"credential": credential, "claimed_resource": "https://reports.invalid"},
    }


def _hop(span_id: str, actor: str, boundary: str, digest: str | None) -> dict[str, Any]:
    credential: dict[str, Any] = {"kind": "bearer"}
    if digest is not None:
        credential["digest"] = digest
    return {
        "span_id": span_id,
        "kind": "tool_execution",
        "name": boundary,
        "delegations": [{"actor": actor, "boundary": boundary, "credential": credential}],
    }


# Ordering: authority recorded after the action it would have covered.


def test_control_a_scope_used_with_no_grant_at_all_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["consent", "delegation"], _use(["docs:read", "docs:write"]))

    assert _CONSENT in run.findings


def test_a_grant_recorded_after_the_scope_was_used_does_not_cover_it(tmp_path: Path) -> None:
    run = _analyze(
        tmp_path,
        ["consent", "delegation"],
        _use(["docs:read", "docs:write"]),
        _grant("s2", ["docs:read", "docs:write"]),
    )

    assert run.answered(_CONSENT), run


def test_control_a_later_approval_recorded_as_not_requested_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["approval", "effects"], _charge(), _approval("not_requested"))

    assert _APPROVAL in run.findings


def test_an_approval_recorded_after_the_payment_does_not_cover_it(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["approval", "effects"], _charge(), _approval("granted"))

    assert run.answered(_APPROVAL), run


# A channel the rule reads that the producer does not record.


def test_control_a_rule_needing_an_unrecorded_dimension_is_skipped(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["consent"], _grant("s1", ["docs:read"]))

    assert _PASSTHROUGH not in run.rules_run


def test_the_consent_rule_does_not_run_without_delegation_recorded(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["consent"], _grant("s1", ["docs:read"]))

    assert _CONSENT not in run.rules_run or run.answered(_CONSENT), run


def test_the_policy_rule_does_not_run_without_tools_or_effects_recorded(tmp_path: Path) -> None:
    denial = {
        "span_id": "s1",
        "kind": "tool_execution",
        "name": "policy",
        "policy_decisions": [{"outcome": "deny", "action": "transfer_funds"}],
    }

    run = _analyze(tmp_path, ["policy"], denial)

    assert _POLICY not in run.rules_run or run.answered(_POLICY), run


# Relevant records lacking what the comparison needs.


def test_control_a_token_outside_its_audience_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["identity"], _presented(["https://billing.invalid/"]))

    assert _IDENTITY in run.findings


def test_a_presented_token_with_no_audience_is_not_a_pass(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["identity"], _presented([]))

    assert run.answered(_IDENTITY), run


@pytest.mark.parametrize("kind", [None, "other"], ids=["kind-omitted", "kind-other"])
def test_a_credential_whose_kind_is_not_stated_and_has_no_audience_is_not_a_pass(
    tmp_path: Path, kind: str | None
) -> None:
    run = _analyze(tmp_path, ["identity"], _presented([], kind))

    assert _IDENTITY in run.unverified, run


def test_control_an_api_key_with_no_audience_is_not_audience_bound(tmp_path: Path) -> None:
    run = _analyze(tmp_path, ["identity"], _presented([], "api_key"))

    assert not run.answered(_IDENTITY), run


def test_control_one_digest_across_two_boundaries_is_a_finding(tmp_path: Path) -> None:
    run = _analyze(
        tmp_path,
        ["delegation"],
        _hop("s1", "agent", "agent->gateway", "sha256:caller"),
        _hop("s2", "gateway", "gateway->billing", "sha256:caller"),
    )

    assert _PASSTHROUGH in run.findings


def test_two_credentialed_hops_without_digests_are_not_a_pass(tmp_path: Path) -> None:
    run = _analyze(
        tmp_path,
        ["delegation"],
        _hop("s1", "agent", "agent->gateway", None),
        _hop("s2", "gateway", "gateway->billing", None),
    )

    assert run.answered(_PASSTHROUGH), run
