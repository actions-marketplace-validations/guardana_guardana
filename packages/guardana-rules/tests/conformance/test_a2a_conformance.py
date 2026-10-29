"""Guardana's A2A target and rules against agents built on the `a2a-sdk`, one test per row.

Each fixture's wire, card route, task store and error codes are the SDK's, so these
tests are where Guardana's reading of A2A v1 meets one it did not write. The run goes
through the `Verifier` and the real pinned client, over loopback.
"""

from collections.abc import Iterator
from urllib.parse import urlsplit

import a2a_servers as a2a
import pytest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.report import Finding, SkipReason
from guardana.core.severity import Severity
from guardana.core.target import A2aAgentTarget
from guardana.core.verify import Verification, Verifier
from sdk_harness import Factory, Origin, serving

_CARD = "guardana.a2a.agent_card"
_CALLERS = "guardana.a2a.caller_identity"
_TASKS = "guardana.a2a.task_visibility"


@pytest.fixture
def origin(request: pytest.FixtureRequest) -> Iterator[Origin]:
    factory: Factory = request.param
    with serving(factory) as served:
        yield served


def _verify(origin: Origin) -> Verification:
    target = A2aAgentTarget(
        origin.url, credential=a2a.CREDENTIAL_A, other_credential=a2a.CREDENTIAL_B
    )
    return Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS)).run(target)


def _of(verification: Verification, rule_id: str) -> tuple[list[Finding], list[Finding]]:
    """The findings and the inconclusive verdicts one rule reported."""
    result = verification.result
    return (
        [f for f in result.findings if f.rule_id == rule_id],
        [f for f in result.unverified if f.rule_id == rule_id],
    )


def _a2a_reported(verification: Verification) -> list[str]:
    result = verification.result
    return [
        f.rule_id
        for f in (*result.findings, *result.unverified)
        if f.rule_id.startswith("guardana.a2a.")
    ]


@pytest.mark.parametrize("origin", [a2a.owner_bound], indirect=True)
def test_an_owner_bound_agent_with_both_callers_draws_no_finding(origin: Origin) -> None:
    verification = _verify(origin)

    assert _a2a_reported(verification) == []
    assert {_CARD, _CALLERS, _TASKS} <= set(verification.result.rules_run)
    assert verification.result.protocols == {"a2a": "1.0"}
    assert verification.manifest.coverage.protocols == {"a2a": "1.0"}
    sent = [(seen.method, seen.authorization) for seen in origin.seen if seen.method == "POST"]
    assert (("POST", f"Bearer {a2a.CREDENTIAL_B}")) in sent, "the second caller was never asked"


@pytest.mark.parametrize("origin", [a2a.security_unenforced], indirect=True)
def test_a_declared_requirement_nothing_enforces_is_high(origin: Origin) -> None:
    findings, _open = _of(_verify(origin), _CALLERS)

    assert [f.severity for f in findings] == [Severity.HIGH]
    assert "requires a credential" in findings[0].evidence.summary


@pytest.mark.parametrize("origin", [a2a.no_security], indirect=True)
def test_no_declared_security_on_loopback_is_low(origin: Origin) -> None:
    verification = _verify(origin)
    findings, _open = _of(verification, _CALLERS)

    assert [f.severity for f in findings] == [Severity.LOW]
    assert "loopback or private" in findings[0].evidence.summary
    assert _of(verification, _CARD) == ([], [])


@pytest.mark.parametrize("origin", [a2a.constant_owner], indirect=True)
def test_a_constant_owner_shows_the_first_callers_task_to_the_second(origin: Origin) -> None:
    verification = _verify(origin)
    findings, unsettled = _of(verification, _TASKS)

    assert [f.severity for f in findings] == [Severity.HIGH]
    assert "second caller read 1 of 1" in findings[0].evidence.summary
    assert unsettled == []
    assert _of(verification, _CALLERS) == ([], [])


@pytest.mark.parametrize("origin", [a2a.extended_card_anonymous], indirect=True)
def test_an_extended_card_served_anonymously_is_high(origin: Origin) -> None:
    findings, _open = _of(_verify(origin), _CALLERS)

    assert [f.severity for f in findings] == [Severity.HIGH]
    assert "extended card" in findings[0].evidence.summary


@pytest.mark.parametrize("origin", [a2a.get_task_unguarded], indirect=True)
def test_a_get_task_route_without_authentication_shows_the_first_callers_task(
    origin: Origin,
) -> None:
    verification = _verify(origin)
    findings, unsettled = _of(verification, _TASKS)
    identity, identity_open = _of(verification, _CALLERS)

    summaries = sorted(f.evidence.summary for f in findings)
    assert [f.severity for f in findings] == [Severity.HIGH, Severity.HIGH]
    assert "presented no credential read the first caller's task" in summaries[0]
    assert "second caller read 1 of 1" in summaries[1]
    assert unsettled == []
    assert identity == []
    assert len(identity_open) == 1
    assert "GetTask" in identity_open[0].evidence.summary
    anonymous = [seen for seen in origin.seen if seen.method == "POST" and not seen.authorization]
    assert len(anonymous) == 3, "random GetTask, ListTasks, and GetTask on the listed task"


@pytest.mark.parametrize("origin", [a2a.no_list_tasks], indirect=True)
def test_an_agent_without_list_tasks_is_recorded_as_not_offered(origin: Origin) -> None:
    result = _verify(origin).result

    skipped = {s.rule_id: s for s in result.rules_skipped}
    assert skipped[_TASKS].reason is SkipReason.NOT_OFFERED
    assert skipped[_TASKS].missing == ("ListTasks",)
    assert _TASKS not in result.rules_run


@pytest.mark.parametrize("origin", [a2a.card_defects], indirect=True)
def test_a_card_missing_a_field_and_naming_an_undeclared_scheme_fires_once(origin: Origin) -> None:
    findings, _open = _of(_verify(origin), _CARD)

    assert len(findings) == 1
    summary = findings[0].evidence.summary
    assert "no description" in summary
    assert f"names {a2a.UNDECLARED_SCHEME}" in summary


@pytest.mark.parametrize("origin", [a2a.interface_elsewhere], indirect=True)
def test_an_interface_on_another_origin_leaves_every_call_rule_inconclusive(
    origin: Origin,
) -> None:
    verification = _verify(origin)

    for rule_id in (_CALLERS, _TASKS):
        findings, unsettled = _of(verification, rule_id)
        assert findings == []
        assert len(unsettled) == 1
        assert "run --a2a against that origin" in unsettled[0].evidence.summary
    assert [(seen.method, seen.path) for seen in origin.seen] == [("GET", a2a.CARD_PATH)]
    assert {seen.host for seen in origin.seen} == {urlsplit(origin.url).netloc}
