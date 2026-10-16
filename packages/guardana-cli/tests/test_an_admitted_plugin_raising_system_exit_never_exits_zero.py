"""An admitted rule or evaluator raising `SystemExit` after discovery never ends a command at 0."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import EVALUATOR_GROUP, RULE_GROUP
from typer.testing import CliRunner

runner = CliRunner()

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
"""Protocol 2: GLOBAL os.system, one string argument, REDUCE."""

_APPLICABILITY_MODULE = """\
from guardana.core.rule import Rule, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.taxonomy import OWASP_LLM03_2026


class Hooked(Rule):
    meta = RuleMeta(
        id="acme.exit.applicability",
        title="hooked",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03_2026,),
    )

    def not_applicable_to(self, target):
        {action}

    def run(self, target, ctx):
        return iter(())


def provide():
    return [Hooked()]
"""

_FIXTURE_MODULE = """\
from guardana.core.rule import Rule, RuleMeta
from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome, materialise
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.taxonomy import OWASP_LLM03_2026
from guardana.core.testing import files_target


class Sampled(Rule):
    meta = RuleMeta(
        id="acme.exit.fixture",
        title="sampled",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03_2026,),
    )

    def fixtures(self):
        return materialise(
            (
                DeclaredFixture(
                    "clean", FixtureOutcome.CLEAN, lambda: files_target({{"a.txt": "x"}})
                ),
            )
        )

    def run(self, target, ctx):
        {action}


def provide():
    return [Sampled()]
"""

_EVALUATOR_MODULE = """\
from guardana.core.evaluator.base import Evaluator


class Grader(Evaluator):
    id = "acme_exit"

    def evaluate(self, exchange, expectation):
        {action}


def provide():
    return [Grader()]
"""


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _admit(site: FakeSite, group: str, template: str, action: str) -> list[str]:
    module = site.module(template.format(action=action))
    site.distribution("exit-pack", (group, "exit-pack", module.name))
    return ["--plugins", "allowlist", "--allow-plugin", "exit-pack"]


def _scan(site: FakeSite, tmp_path: Path, action: str) -> int:
    model = tmp_path / "model"
    model.mkdir()
    (model / "weights.pkl").write_bytes(_SYSTEM)
    trust = _admit(site, RULE_GROUP, _APPLICABILITY_MODULE, action)
    return runner.invoke(app, ["scan", str(model), *trust]).exit_code


def _rule_test(site: FakeSite, action: str) -> int:
    trust = _admit(site, RULE_GROUP, _FIXTURE_MODULE, action)
    return runner.invoke(app, ["rule", "test", "acme.exit.fixture", *trust]).exit_code


def _calibrate(site: FakeSite, action: str) -> int:
    trust = _admit(site, EVALUATOR_GROUP, _EVALUATOR_MODULE, action)
    return runner.invoke(app, ["calibrate", "--evaluator", "acme_exit", *trust]).exit_code


def test_control_a_quiet_applicability_hook_leaves_the_malicious_pickle_reported(
    site: FakeSite, tmp_path: Path
) -> None:
    assert _scan(site, tmp_path, "return None") == ExitCode.POLICY_FAILED


def test_an_applicability_hook_raising_system_exit_never_ends_the_scan_with_ok(
    site: FakeSite, tmp_path: Path
) -> None:
    assert _scan(site, tmp_path, "raise SystemExit(0)") != ExitCode.OK


def test_control_a_fixture_whose_rule_raises_is_an_error(site: FakeSite) -> None:
    assert _rule_test(site, "raise RuntimeError('broken')") == ExitCode.INDETERMINATE


def test_a_fixture_whose_rule_raises_system_exit_never_ends_rule_test_with_ok(
    site: FakeSite,
) -> None:
    assert _rule_test(site, "raise SystemExit(0)") != ExitCode.OK


def test_control_an_evaluator_that_raises_fails_the_calibration(site: FakeSite) -> None:
    assert _calibrate(site, "raise RuntimeError('broken')") != ExitCode.OK


def test_an_evaluator_raising_system_exit_never_ends_calibrate_with_ok(site: FakeSite) -> None:
    assert _calibrate(site, "raise SystemExit(0)") != ExitCode.OK
