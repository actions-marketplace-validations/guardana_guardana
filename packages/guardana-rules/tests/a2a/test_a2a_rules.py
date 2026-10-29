"""The three A2A rules, graded against scripted agents built for each shape they name."""

import json
from collections.abc import Mapping
from typing import Any

import pytest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import Finding, SkipReason, StopReason
from guardana.core.rule import NotOffered, RuleContext
from guardana.core.severity import Severity
from guardana.core.target import A2aAgentTarget, EndpointUnreachable
from guardana.core.target._mcp_http import DiscoveryScope, McpError, RawReply
from guardana.core.testing import ScriptedA2aAgent
from guardana.core.testing.a2a import agent_card
from guardana.core.verify import Verifier
from guardana.rules.a2a import A2aAgentCardRule, A2aCallerIdentityRule, A2aTaskVisibilityRule

PUBLIC = "https://agent.invalid/"
LOCAL = "http://127.0.0.1:8080/"
A = "rules-caller-a"
B = "rules-caller-b"
TASK = "3f6a1d8e-2b4c-4e7a-9d1f-5c8b0a2e6f74"


def _target(
    url: str = PUBLIC,
    *,
    credential: str | None = A,
    other: str | None = B,
    card: dict[str, Any] | None = None,
    **agent: Any,  # noqa: ANN401 — the double's own keywords
) -> A2aAgentTarget:
    agent.setdefault("tasks", {"alice": [TASK]})
    agent.setdefault("callers", {A: "alice", B: "bob"})
    scripted = ScriptedA2aAgent(url, card=card, **agent)
    return A2aAgentTarget(url, credential=credential, other_credential=other, sender=scripted)


def _card(url: str = PUBLIC, **overrides: object) -> dict[str, Any]:
    return {**agent_card(f"{url}a2a"), **overrides}


def _run(
    rule: A2aAgentCardRule | A2aCallerIdentityRule | A2aTaskVisibilityRule, target: A2aAgentTarget
) -> list[Finding]:
    return list(rule.run(target, RuleContext()))


def _inconclusive(findings: list[Finding]) -> list[str]:
    return [f.evidence.summary for f in findings if f.verdict is not None]


def _fired(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is None]


# --- guardana.a2a.agent_card ---


def test_a_complete_card_is_silent() -> None:
    assert _run(A2aAgentCardRule(), _target()) == []


def test_every_card_defect_is_listed_in_one_finding() -> None:
    card = _card(
        name="",
        skills=[],
        securityRequirements=[{"schemes": {"bearer": {}}}, {"schemes": {"partner": {}}}],
    )
    card.pop("version")

    findings = _run(A2aAgentCardRule(), _target(card=card))

    assert len(findings) == 1
    summary = findings[0].evidence.summary
    assert findings[0].severity is Severity.MEDIUM
    for said in ("no name", "no version", "no skills", "names partner"):
        assert said in summary
    assert "names bearer" not in summary


def test_a_plain_http_interface_fires_only_on_a_host_that_is_not_local() -> None:
    public = "http://agent.invalid/"
    assert (
        "plain http"
        in _run(A2aAgentCardRule(), _target(public, card=_card(public)))[0].evidence.summary
    )
    assert _run(A2aAgentCardRule(), _target(LOCAL, card=_card(LOCAL))) == []


def test_a_plain_http_interface_is_judged_by_its_own_host_not_the_cards() -> None:
    elsewhere = _card("http://public.example/")
    loopback = _card(PUBLIC, supportedInterfaces=_card(LOCAL)["supportedInterfaces"])

    fired = _run(A2aAgentCardRule(), _target(LOCAL, card=elsewhere))

    assert "plain http" in fired[0].evidence.summary
    assert _run(A2aAgentCardRule(), _target(card=loopback)) == []


def test_a_card_the_agent_would_not_serve_is_inconclusive() -> None:
    findings = _run(A2aAgentCardRule(), _target(statuses={"card": 410}))

    assert _inconclusive(findings) == [
        "the agent card could not be read: https://agent.invalid/.well-known/agent-card.json "
        "was answered HTTP 410"
    ]


# --- guardana.a2a.caller_identity ---


def test_an_enforced_requirement_is_silent() -> None:
    assert _run(A2aCallerIdentityRule(), _target()) == []


def test_a_required_credential_nobody_checks_is_high() -> None:
    findings = _run(A2aCallerIdentityRule(), _target(enforced=False))

    assert [(f.severity, f.verdict) for f in findings] == [(Severity.HIGH, None)]
    assert "answered ListTasks" in findings[0].evidence.summary
    assert "GetTask" not in findings[0].evidence.summary, "a task not found is never graded"


def test_no_declared_security_is_high_on_a_public_host_and_low_on_a_local_one() -> None:
    public = _run(
        A2aCallerIdentityRule(),
        _target(card=_card(securitySchemes={}, securityRequirements=[]), enforced=False),
    )
    local = _run(
        A2aCallerIdentityRule(),
        _target(LOCAL, card=agent_card(f"{LOCAL}a2a", bearer=False), enforced=False),
    )

    assert [f.severity for f in public] == [Severity.HIGH]
    assert [f.severity for f in local] == [Severity.LOW]


def test_an_optional_requirement_makes_an_anonymous_answer_what_was_declared() -> None:
    card = _card(securityRequirements=[{"schemes": {"bearer": {}}}, {"schemes": {}}])

    assert _run(A2aCallerIdentityRule(), _target(card=card, enforced=False)) == []


def test_an_extended_card_served_anonymously_is_one_high_finding_under_any_security() -> None:
    card = _card(capabilities={"extendedAgentCard": True})
    findings = _run(
        A2aCallerIdentityRule(),
        _target(card=card, anonymous_methods={"GetExtendedAgentCard"}),
    )
    optional = _run(
        A2aCallerIdentityRule(),
        _target(
            card={**card, "securityRequirements": [{"schemes": {}}]},
            anonymous_methods={"GetExtendedAgentCard"},
        ),
    )

    assert [f.severity for f in _fired(findings)] == [Severity.HIGH]
    assert "extended card" in findings[0].evidence.summary
    assert [f.evidence.summary for f in optional] == [findings[0].evidence.summary]


def test_get_task_as_an_unknown_method_before_any_a2a_code_is_inconclusive() -> None:
    findings = _run(
        A2aCallerIdentityRule(), _target(errors={"GetTask": -32601}, anonymous_methods={"GetTask"})
    )

    assert len(_inconclusive(findings)) == 1
    assert "unknown method" in findings[0].evidence.summary


def test_every_anonymous_read_answered_otherwise_is_inconclusive() -> None:
    findings = _run(A2aCallerIdentityRule(), _target(statuses={"GetTask": 502, "ListTasks": 400}))

    assert len(_inconclusive(findings)) == 1
    assert (
        "GetTask: a reply that is not a JSON-RPC result or error (HTTP 502)"
        in findings[0].evidence.summary
    )


def test_an_agent_neither_refusing_nor_answering_an_anonymous_read_is_inconclusive() -> None:
    findings = _run(A2aCallerIdentityRule(), _target(enforced=False, errors={"ListTasks": -32004}))

    assert len(_inconclusive(findings)) == 1
    assert "neither refused nor answered" in findings[0].evidence.summary
    assert "GetTask: JSON-RPC error -32001" in findings[0].evidence.summary


def test_an_agent_refusing_a2a_1_0_is_inconclusive_for_both_call_rules() -> None:
    target = _target(errors={"GetTask": -32009}, enforced=False)

    assert len(_inconclusive(_run(A2aCallerIdentityRule(), target))) == 1
    assert len(_inconclusive(_run(A2aTaskVisibilityRule(), target))) == 1


# --- guardana.a2a.task_visibility ---


def test_tasks_bound_to_their_owner_are_silent() -> None:
    assert _run(A2aTaskVisibilityRule(), _target()) == []


def test_a_second_caller_reading_the_first_callers_task_is_high() -> None:
    findings = _run(A2aTaskVisibilityRule(), _target(owner_bound=False))

    assert [(f.severity, f.verdict) for f in findings] == [(Severity.HIGH, None)]
    assert "second caller read 1 of 1" in findings[0].evidence.summary
    assert TASK not in findings[0].evidence.summary


def test_an_anonymous_listing_showing_a_task_is_high() -> None:
    findings = _run(
        A2aTaskVisibilityRule(),
        _target(enforced=False, owner_bound=False, credential=None, other=None),
    )

    assert [f.severity for f in _fired(findings)] == [Severity.HIGH]
    assert "1 task(s) to a caller presenting no credential" in findings[0].evidence.summary
    assert len(_inconclusive(findings)) == 1, "the cross-caller half still had no credentials"


class _AnonymousListingFails(ScriptedA2aAgent):
    """Answers an anonymous `ListTasks` with an internal error, and everything else as scripted."""

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        anonymous = "Authorization" not in (headers or {})
        if anonymous and body is not None and b'"ListTasks"' in body:
            error = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "x"}}
            return RawReply(200, {"Content-Type": "application/json"}, json.dumps(error).encode())
        return super().__call__(
            url, method=method, body=body, headers=headers, alongside=alongside, discovery=discovery
        )


def test_an_anonymous_listing_answered_otherwise_leaves_that_half_open() -> None:
    agent = _AnonymousListingFails(PUBLIC, callers={A: "alice", B: "bob"}, tasks={"alice": [TASK]})
    target = A2aAgentTarget(PUBLIC, credential=A, other_credential=B, sender=agent)

    findings = _run(A2aTaskVisibilityRule(), target)

    assert _fired(findings) == []
    assert _inconclusive(findings) == [
        "whether a caller presenting no credential is shown tasks is unknown: ListTasks met "
        "JSON-RPC error -32603 (HTTP 200)"
    ]


def test_a_second_caller_who_is_refused_leaves_the_cross_caller_half_open() -> None:
    target = _target(callers={A: "alice"})
    findings = _run(A2aTaskVisibilityRule(), target)

    assert len(_inconclusive(findings)) == 1
    assert "--a2a-other-token-env" in findings[0].evidence.summary


def test_a_first_caller_with_no_task_leaves_the_cross_caller_half_open() -> None:
    findings = _run(A2aTaskVisibilityRule(), _target(tasks={}))

    assert len(_inconclusive(findings)) == 1
    assert "listed no task" in findings[0].evidence.summary


def test_credentials_the_card_cannot_take_leave_the_cross_caller_half_open() -> None:
    card = _card(
        securitySchemes={"key": {"apiKeySecurityScheme": {"name": "X-Key"}}},
        securityRequirements=[{"schemes": {"key": {}}}],
    )
    findings = _run(A2aTaskVisibilityRule(), _target(card=card))

    assert len(_inconclusive(findings)) == 1
    assert "key (apiKeySecurityScheme)" in findings[0].evidence.summary


@pytest.mark.parametrize(
    ("enforced", "credential"), [(True, A), (False, None)], ids=["the first caller", "anonymous"]
)
def test_every_list_tasks_answered_unsupported_is_not_offered(
    enforced: bool, credential: str | None
) -> None:
    target = _target(
        enforced=enforced,
        credential=credential,
        other=None if credential is None else B,
        errors={"ListTasks": -32004},
    )

    with pytest.raises(NotOffered) as raised:
        _run(A2aTaskVisibilityRule(), target)
    assert raised.value.missing == ("ListTasks",)


def test_a_list_tasks_that_was_only_refused_is_not_read_as_not_offered() -> None:
    findings = _run(A2aTaskVisibilityRule(), _target(credential=None, other=None))

    assert len(_inconclusive(findings)) == 1
    assert "--a2a-token-env" in findings[0].evidence.summary


class _AnonymousGetTaskUnscoped(ScriptedA2aAgent):
    """Lets an anonymous `GetTask` past authentication and serves it any stored task."""

    def __init__(self, url: str, **agent: Any) -> None:  # noqa: ANN401 — the double's keywords
        super().__init__(url, anonymous_methods={"GetTask"}, **agent)

    def _read(self, method: str, params: Mapping[str, Any], owner: str | None) -> RawReply:
        stored = {task_id for ids in self.tasks.values() for task_id in ids}
        if method == "GetTask" and owner is None and params.get("id") in stored:
            task = {"id": params["id"], "status": {"state": "TASK_STATE_COMPLETED"}}
            payload = {"jsonrpc": "2.0", "id": 1, "result": task}
            return RawReply(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())
        return super()._read(method, params, owner)


def _unscoped_get_task() -> A2aAgentTarget:
    agent = _AnonymousGetTaskUnscoped(
        PUBLIC, callers={A: "alice", B: "bob"}, tasks={"alice": [TASK]}
    )
    return A2aAgentTarget(PUBLIC, credential=A, other_credential=B, sender=agent)


def test_a_task_a_caller_presenting_nothing_reads_by_id_is_high() -> None:
    findings = _run(A2aTaskVisibilityRule(), _unscoped_get_task())

    assert [(f.severity, f.verdict) for f in findings] == [(Severity.HIGH, None)]
    assert (
        "a caller who presented no credential read the first caller's task"
        in findings[0].evidence.summary
    )
    assert TASK not in findings[0].evidence.summary


class _AnonymousGetTaskNotOffered(_AnonymousGetTaskUnscoped):
    """Answers the anonymous `GetTask` on a stored task as an operation it does not offer."""

    def _read(self, method: str, params: Mapping[str, Any], owner: str | None) -> RawReply:
        stored = {task_id for ids in self.tasks.values() for task_id in ids}
        if method == "GetTask" and owner is None and params.get("id") in stored:
            error = {"code": -32004, "message": "unsupported operation"}
            payload = {"jsonrpc": "2.0", "id": 1, "error": error}
            return RawReply(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())
        return super()._read(method, params, owner)


def test_an_anonymous_read_of_a_listed_task_answered_as_not_offered_is_inconclusive() -> None:
    agent = _AnonymousGetTaskNotOffered(
        PUBLIC, callers={A: "alice", B: "bob"}, tasks={"alice": [TASK]}
    )
    target = A2aAgentTarget(PUBLIC, credential=A, other_credential=B, sender=agent)

    findings = _run(A2aTaskVisibilityRule(), target)

    assert _fired(findings) == []
    assert any("can read the first caller's task" in said for said in _inconclusive(findings))


def test_a_required_credential_met_with_task_not_found_is_inconclusive_naming_the_method() -> None:
    findings = _run(A2aCallerIdentityRule(), _unscoped_get_task())

    assert _fired(findings) == []
    assert len(_inconclusive(findings)) == 1
    assert "GetTask" in findings[0].evidence.summary
    assert "ListTasks" not in findings[0].evidence.summary


def test_an_optional_requirement_with_nothing_decisive_and_no_extended_card_is_silent() -> None:
    card = _card(securityRequirements=[{"schemes": {"bearer": {}}}, {"schemes": {}}])

    findings = _run(
        A2aCallerIdentityRule(), _target(card=card, enforced=False, errors={"ListTasks": -32004})
    )

    assert findings == []


def test_an_optional_requirement_with_an_extended_card_left_undecided_is_inconclusive() -> None:
    card = _card(
        securityRequirements=[{"schemes": {"bearer": {}}}, {"schemes": {}}],
        capabilities={"extendedAgentCard": True},
    )

    findings = _run(
        A2aCallerIdentityRule(),
        _target(
            card=card,
            enforced=False,
            errors={"ListTasks": -32004, "GetExtendedAgentCard": -32603},
        ),
    )

    assert len(_inconclusive(findings)) == 1


def test_a_finding_records_the_interface_examined() -> None:
    findings = _run(A2aCallerIdentityRule(), _target(enforced=False))

    assert "interface=https://agent.invalid/a2a" in findings[0].evidence.detail


def test_a_plain_http_interface_judged_by_its_url_alone_is_not_shown_to_be_local() -> None:
    elsewhere = _card("http://public.example/")

    card = _run(A2aAgentCardRule(), _target(LOCAL, card=elsewhere))

    assert "not shown to be loopback or private" in card[0].evidence.summary


class _SecondCallerDropped(ScriptedA2aAgent):
    """Drops the connection on the second caller's request, answering everything else."""

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        if (headers or {}).get("Authorization") == f"Bearer {B}":
            raise McpError(f"could not reach {url}: the connection was reset")
        return super().__call__(
            url, method=method, body=body, headers=headers, alongside=alongside, discovery=discovery
        )


def _listing_open_and_second_caller_dropped() -> A2aAgentTarget:
    agent = _SecondCallerDropped(
        PUBLIC,
        callers={A: "alice", B: "bob"},
        tasks={"alice": [TASK]},
        anonymous_methods={"ListTasks"},
        owner_bound=False,
    )
    return A2aAgentTarget(PUBLIC, credential=A, other_credential=B, sender=agent)


def test_the_anonymous_listing_is_reported_before_the_second_caller_stops_the_run() -> None:
    rule = A2aTaskVisibilityRule()
    produced: list[Finding] = []

    with pytest.raises(EndpointUnreachable):
        produced.extend(rule.run(_listing_open_and_second_caller_dropped(), RuleContext()))

    assert [f.severity for f in produced] == [Severity.HIGH]
    assert "to a caller presenting no credential" in produced[0].evidence.summary


@pytest.mark.parametrize("concurrency", [1, 4])
def test_a_stopped_run_keeps_the_same_findings_whatever_the_concurrency(concurrency: int) -> None:
    verifier = Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), concurrency=concurrency)

    outcomes = set()
    for _ in range(12):
        result = verifier.run(_listing_open_and_second_caller_dropped()).result
        assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
        outcomes.add(tuple(sorted((f.rule_id, f.severity.name) for f in result.findings)))

    assert outcomes == {
        (
            ("guardana.a2a.caller_identity", "HIGH"),
            ("guardana.a2a.task_visibility", "HIGH"),
        )
    }


def test_a_run_records_an_agent_without_listing_as_a_not_offered_skip() -> None:
    verifier = Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS))
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    assert "guardana.a2a.task_visibility" in {r.meta.id for r in registry.rules()}

    verification = verifier.run(_target(errors={"ListTasks": -32004}))

    skipped = {s.rule_id: s for s in verification.result.rules_skipped}
    assert skipped["guardana.a2a.task_visibility"].reason is SkipReason.NOT_OFFERED
    assert "guardana.a2a.task_visibility" not in verification.result.rules_run
    assert verification.result.protocols == {"a2a": "1.0"}
