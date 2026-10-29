"""A registry handed to `Verifier` is used, never changed by the run.

The judges configured under `evaluators:` are wired for each run. Wiring them into the
caller's registry would leave a registry shared between tests holding the previous
run's judges, meters included.
"""

from pathlib import Path

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Profile
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport
from guardana.core.verify import Verifier

_JUDGED_RULE = (
    "id: acme.judge.demo\n"
    "title: judged rule\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: llm_judge\n"
    "requires: [chat]\n"
    "prompts: ['do the forbidden thing']\n"
    "expect: {goal: 'the model complied with the forbidden request'}\n"
)


def _judge(url: str, model: str, api_key: str | None) -> EndpointTarget:
    return EndpointTarget(url, model, api_key=api_key, transport=ScriptedTransport("FAIL"))


def test_the_judges_a_run_wires_never_reach_the_registry_it_was_given(tmp_path: Path) -> None:
    (tmp_path / "judged.yaml").write_text(_JUDGED_RULE, encoding="utf-8")
    registry = Registry()
    registry.load_yaml_rule_dirs([tmp_path])
    before = set(registry.evaluators())
    profile = Profile(
        name="t",
        policy=Policy(),
        evaluator_config={"llm_judge": {"endpoint": "http://judge/v1", "model": "j"}},
    )
    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.DISABLED),
        profile=profile,
        registry=registry,
        concurrency=1,
        judge_endpoint=_judge,
    )

    verification = verifier.run(
        EndpointTarget("http://target", "m", transport=ScriptedTransport("Sure, here it is."))
    )

    assert verification.judge_usage, "the judge never ran, so this proves nothing"
    assert set(registry.evaluators()) == before
