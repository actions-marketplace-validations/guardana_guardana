"""An admitted provider that raises `SystemExit` never ends a scan as a pass."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import RULE_GROUP
from typer.testing import CliRunner

runner = CliRunner()

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
"""Protocol 2: GLOBAL os.system, one string argument, REDUCE."""

_EXITING_MODULE = """\
def provide():
    raise SystemExit(0)
"""

_QUIET_MODULE = """\
def provide():
    return []
"""


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _model(tmp_path: Path) -> Path:
    model = tmp_path / "model"
    model.mkdir()
    (model / "weights.pkl").write_bytes(_SYSTEM)
    return model


def test_control_an_admitted_quiet_pack_leaves_the_malicious_pickle_reported(
    site: FakeSite, tmp_path: Path
) -> None:
    module = site.module(_QUIET_MODULE)
    site.distribution("exit-rules", (RULE_GROUP, "exit-rules", module.name))

    result = runner.invoke(
        app,
        ["scan", str(_model(tmp_path)), "--plugins", "allowlist", "--allow-plugin", "exit-rules"],
    )

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output


def test_a_provider_raising_system_exit_never_ends_the_scan_with_ok(
    site: FakeSite, tmp_path: Path
) -> None:
    module = site.module(_EXITING_MODULE)
    site.distribution("exit-rules", (RULE_GROUP, "exit-rules", module.name))

    result = runner.invoke(
        app,
        ["scan", str(_model(tmp_path)), "--plugins", "allowlist", "--allow-plugin", "exit-rules"],
    )

    assert result.exit_code != ExitCode.OK, result.output
