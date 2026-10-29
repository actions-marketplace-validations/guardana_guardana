"""A value a target learns during the run is withheld from what the run writes.

The withheld set is read again after the last request, so a task id an A2A agent
revealed half way through never reaches a saved run, whatever evidence quoted it. These
tests run an A2A target through the `Verifier` and look in the document it would save.
"""

import json
from collections.abc import Iterator

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import A2aAgentTarget, Capability, Target, TargetKind
from guardana.core.target.protocols import A2aInspector
from guardana.core.testing import ScriptedA2aAgent
from guardana.core.verify import Verification, Verifier

_URL = "https://agent.invalid/"
_A = "verify-caller-a-token"
_B = "verify-caller-b-token"
_TASK = "1e5b9c3a-7d2f-4a8b-9c6e-0f1a2b3c4d5e"


class _Echo(Rule):
    """Reports every task id the agent revealed, as a careless rule might."""

    meta = RuleMeta(
        id="acme.a2a.echo",
        title="echo",
        severity=Severity.LOW,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.INSPECT_A2A}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterator[Finding]:
        """Buy the callers' section, then quote the id it learned and both credentials."""
        if not isinstance(target, A2aInspector):
            return
        target.a2a().callers  # noqa: B018 — the read buys the section
        yield Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=(),
            target_ref=target.ref,
            evidence=Evidence(summary=f"saw {_TASK} as {_A} and {_B}"),
        )


def _verify() -> tuple[Verification, ScriptedA2aAgent]:
    agent = ScriptedA2aAgent(
        _URL, callers={_A: "alice", _B: "bob"}, tasks={"alice": [_TASK]}, owner_bound=False
    )
    registry = Registry()
    registry.register_rule(_Echo())
    verifier = Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), registry=registry)
    verification = verifier.run(
        A2aAgentTarget(_URL, credential=_A, other_credential=_B, sender=agent)
    )
    return verification, agent


def test_a_task_id_learned_during_the_run_never_reaches_the_saved_run() -> None:
    verification, _agent = _verify()
    saved = json.dumps(verification.document())

    findings = verification.result.findings
    assert [f.rule_id for f in findings] == ["acme.a2a.echo"], verification.result.errors
    assert findings[0].evidence.summary.startswith("saw ")
    assert _TASK not in saved
    assert _A not in saved
    assert _B not in saved


def test_an_a2a_agent_is_examined_by_its_rules_in_one_pass() -> None:
    _saved, agent = _verify()

    assert [call[0] for call in agent.calls].count("ListTasks") == 2
    assert len([r for r in agent.requests if r[0] == "GET"]) == 1
