"""Three sentences in README.md and FEATURES.md hold for the behaviour they describe."""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import MARKING_MODULE, FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import RULE_GROUP
from guardana.core.report import ReportLoadError
from guardana.core.verify import load_verification
from typer.testing import CliRunner

runner = CliRunner()
_ROOT = Path(__file__).resolve().parents[3]
_NUMBERS = {"seven": 7, "eight": 8, "nine": 9, "ten": 10}


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def test_the_readme_counts_every_exit_code() -> None:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"Exit codes have (\w+) documented meanings", readme)
    assert match is not None

    assert _NUMBERS[match.group(1)] == len(ExitCode)


def test_control_doctor_leaves_a_refused_pack_unimported(site: FakeSite) -> None:
    module = site.module(MARKING_MODULE)
    site.distribution("acme-rules", (RULE_GROUP, "acme-rules", module.name))

    runner.invoke(app, ["doctor"])

    assert not module.marker.exists()


def _features() -> str:
    return " ".join((_ROOT / "FEATURES.md").read_text(encoding="utf-8").split())


def test_doctor_imports_a_pack_only_once_it_is_admitted(site: FakeSite) -> None:
    assert "it imports a pack only when the pack is admitted" in _features()
    module = site.module(MARKING_MODULE)
    site.distribution("acme-rules", (RULE_GROUP, "acme-rules", module.name))

    runner.invoke(app, ["doctor", "--plugins", "allowlist", "--allow-plugin", "acme-rules"])

    assert module.marker.exists()


def test_load_verification_refuses_only_the_schema_1_runs_features_names() -> None:
    assert "`load_verification` reads every run except those of schema 1" in _features()
    historical = _ROOT / "packages" / "guardana-core" / "tests" / "historical" / "run"

    with pytest.raises(ReportLoadError, match="records no gate"):
        load_verification(historical / "0.6.0.json")
    assert load_verification(historical / "0.39.0.json").gate is not None
