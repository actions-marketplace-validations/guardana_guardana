"""`Verifier` refuses what it would silently ignore, and a run it would describe wrongly."""

import dataclasses
import pickle
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.budget import Budgets
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import RefusingTransport
from guardana.core.usage import UsageMeter
from guardana.core.verify import TargetReusedError, UnenforceableBudgetError, Verifier

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (print, ("pwned",))


@pytest.mark.parametrize(
    "extra",
    [{"rule_paths": (Path("team"),)}, {"rules": (object(),)}, {"evaluators": (object(),)}],
)
def test_a_registry_given_whole_cannot_be_combined_with_what_would_load_into_it(
    extra: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="loads nothing into it"):
        Verifier(trust=_BUILTINS, registry=Registry(), **extra)  # type: ignore[arg-type]


def test_a_given_registry_runs_the_trials_the_manifest_records() -> None:
    def requests(trials: int) -> int:
        profile = replace(default_profile(), trials=trials)
        target = EndpointTarget(
            "http://x", "m", transport=RefusingTransport(), meter=UsageMeter(profile.budgets)
        )
        verification = Verifier(
            trust=_BUILTINS, profile=profile, registry=Registry.discover(_BUILTINS), concurrency=1
        ).run(target)
        assert verification.manifest.execution.trials == trials
        usage = target.usage()
        assert usage is not None
        return usage.requests

    assert requests(3) > requests(1)


def test_a_target_that_already_ran_is_refused_instead_of_serving_what_it_cached(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    target = ArtifactTarget(tmp_path)
    verifier = Verifier(trust=_BUILTINS)
    assert verifier.run(target).passed
    (tmp_path / "model.pkl").write_bytes(pickle.dumps(_Evil()))

    with pytest.raises(TargetReusedError, match="already ran"):
        verifier.run(target)
    assert not verifier.run(ArtifactTarget(tmp_path)).passed


def test_a_verifier_cannot_be_reconfigured_after_it_prepared_a_registry() -> None:
    verifier = Verifier(trust=_BUILTINS)

    with pytest.raises(dataclasses.FrozenInstanceError):
        verifier.profile = default_profile()  # type: ignore[misc]


def test_a_target_refused_before_it_ran_can_still_run(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    target = ArtifactTarget(tmp_path)
    timed = replace(default_profile(), budgets=Budgets(max_duration_seconds=1))

    with pytest.raises(UnenforceableBudgetError):
        Verifier(trust=_BUILTINS, profile=timed).run(target)

    assert Verifier(trust=_BUILTINS).run(target).passed


def test_a_target_already_running_is_refused(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    refused: list[TargetReusedError] = []

    class _RunsItsTargetAgain(Rule):
        meta = RuleMeta(
            id="acme.runs_its_target_again",
            title="starts a second run of the target it is reading",
            severity=Severity.LOW,
            target_kind=TargetKind.ARTIFACT,
            required_capabilities=frozenset({Capability.READ_FILES}),
        )

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            if not refused:
                try:
                    verifier.run(target)
                except TargetReusedError as exc:
                    refused.append(exc)
            return ()

    verifier = Verifier(trust=PluginTrust(mode=PluginMode.DISABLED), rules=(_RunsItsTargetAgain(),))

    verifier.run(ArtifactTarget(tmp_path))

    assert refused
