"""A selected suite's regression pairs are regraded before every run, live or from a recording."""

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from guardana.core.gate import GateOutcome
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.probe import plan_target_probe
from guardana.core.profile import Profile, default_profile
from guardana.core.registry import Registry
from guardana.core.report import CheckError
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import ChatMessage, EndpointTarget
from guardana.core.usage import UsageMeter
from guardana.core.verify import Verifier, exchanges_path

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)
_SUITE = "acme.quality.reset"
_QUESTION = "How do I reset my password?"
_ANSWERS = {
    _QUESTION: "Open Settings, then Security.",
    "Where is my invoice?": "Settings lists every invoice.",
}
_HOLDS = ["Settings"]
_BREAKS = ["e"]
"""Found in the observed failure as much as in the correct reply, so it tells neither apart."""


class _ByQuestion:
    """An application that answers each question its own way, and counts what it was sent."""

    def __init__(self) -> None:
        self.sent = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer the last user message from the table."""
        self.sent += 1
        return _ANSWERS[messages[-1].content]


def _suite(directory: Path, regression_expects: list[str]) -> Path:
    rules = directory / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    header = {"guardana_dataset": 2, "name": "support", "version": "1"}
    cases = [
        {"input": "Where is my invoice?", "expect": {"contains_any": ["Settings"]}},
        {
            "input": _QUESTION,
            "expect": {"contains_any": regression_expects},
            "tags": ["regression"],
            "observed": "Please ask someone else.",
            "accepted": "Open Settings, then Security.",
        },
    ]
    lines = [json.dumps(record) for record in (header, *cases)]
    (rules / "reset.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule = {
        "id": _SUITE,
        "title": "The support bot names where to reset a password",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "contains",
        "requires": ["chat"],
        "dataset": "./reset.jsonl",
        "gate": {"min_pass_rate": 1, "min_sample": 2},
    }
    (rules / "reset.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _profile(*, keep: bool = False) -> Profile:
    base = default_profile()
    return replace(
        base,
        policy=replace(base.policy, include=(_SUITE,)),
        privacy=replace(base.privacy, keep_exchanges=keep),
    )


def _endpoint(profile: Profile) -> EndpointTarget:
    return EndpointTarget(
        "http://app.test/v1", "m", transport=_ByQuestion(), meter=UsageMeter(profile.budgets)
    )


def _regression_errors(errors: Sequence[CheckError]) -> list[CheckError]:
    return [error for error in errors if error.stage == "regression"]


def test_a_live_run_over_holding_pairs_passes(tmp_path: Path) -> None:
    profile = _profile()
    verification = Verifier(
        trust=_BUILTINS, profile=profile, rule_paths=(_suite(tmp_path, _HOLDS),)
    ).run(_endpoint(profile))

    assert verification.result.errors == ()
    assert verification.gate is GateOutcome.PASS


def test_a_live_run_records_a_pair_that_no_longer_holds_and_cannot_pass(tmp_path: Path) -> None:
    profile = _profile()
    verification = Verifier(
        trust=_BUILTINS, profile=profile, rule_paths=(_suite(tmp_path, _BREAKS),)
    ).run(_endpoint(profile))

    (error,) = _regression_errors(verification.result.errors)
    assert error.source == _SUITE
    assert "dataset line 3: observed graded pass, accepted graded pass" in error.reason
    assert verification.gate is GateOutcome.INDETERMINATE


def test_grading_a_recording_regrades_the_pairs_of_the_suite_as_it_is_now(
    tmp_path: Path,
) -> None:
    kept = _profile(keep=True)
    run = tmp_path / "run.json"
    Verifier(trust=_BUILTINS, profile=kept, rule_paths=(_suite(tmp_path / "then", _HOLDS),)).run(
        _endpoint(kept)
    ).save(run)

    graded = Verifier(
        trust=_BUILTINS, profile=_profile(), rule_paths=(_suite(tmp_path / "now", _BREAKS),)
    ).grade(exchanges_path(run))

    (error,) = _regression_errors(graded.result.errors)
    assert error.source == _SUITE
    assert graded.gate is GateOutcome.INDETERMINATE


def test_a_plan_names_the_broken_pair_the_run_records(tmp_path: Path) -> None:
    profile = _profile()
    registry = Registry.discover(_BUILTINS)
    for rule in load_yaml_rules(_suite(tmp_path, _BREAKS) / "reset.yaml"):
        registry.register_rule(rule)

    planned = plan_target_probe(registry, profile, _endpoint(profile))
    ran = Verifier(trust=_BUILTINS, profile=profile, rule_paths=(_suite(tmp_path, _BREAKS),)).run(
        _endpoint(profile)
    )

    assert _regression_errors(planned.errors) == _regression_errors(ran.result.errors)
    assert planned.blockers(profile.policy.fail_on)
