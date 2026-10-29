"""Under the unstated default a refusal is told once, by the hint; every other load error still is.

A refusal printed as a warning line and again in the hint reads as two problems, and
a filter that drops refusals must never drop a failure that merely shares a name.
"""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import EXPLODING_MODULE, MARKING_MODULE, FakeModule, FakeSite
from guardana.cli.main import app
from guardana.core.entrypoints import RULE_GROUP
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_HINT = "plugin trust was not stated"
_WARNING = "warning: could not load rule"


def _stderr_lines(result: Result) -> list[str]:
    return [" ".join(line.split()) for line in _ANSI.sub("", result.stderr).splitlines()]


def _mentions(result: Result, text: str) -> int:
    return sum(text in line for line in _stderr_lines(result))


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _refused_pack(site: FakeSite) -> FakeModule:
    module = site.module(MARKING_MODULE)
    site.distribution("acme-rules", (RULE_GROUP, "acme-scanner", module.name))
    return module


def _broken_rule_file(tmp_path: Path) -> Path:
    rules = tmp_path / "checks"
    rules.mkdir()
    (rules / "broken.yaml").write_text("id: acme.broken\n", encoding="utf-8")
    return rules


def test_the_default_tells_a_refusal_once_and_still_prints_other_load_errors(
    site: FakeSite, tmp_path: Path
) -> None:
    _refused_pack(site)

    result = runner.invoke(app, ["rules", "--rules", str(_broken_rule_file(tmp_path))])

    assert _mentions(result, _HINT) == 1
    assert _mentions(result, "acme-rules — 1 entry point(s)") == 1
    assert _mentions(result, "acme-scanner") == 0
    warnings = [line for line in _stderr_lines(result) if line.startswith(_WARNING)]
    assert len(warnings) == 1
    assert "broken.yaml" in warnings[0]


def test_a_failure_that_shares_a_name_with_a_refusal_is_still_printed(site: FakeSite) -> None:
    _refused_pack(site)
    # A distribution spelled as a built-in is admitted by `builtins`; its import fails.
    failing = site.module(EXPLODING_MODULE)
    site.distribution("Guardana_Report", (RULE_GROUP, "acme-scanner", failing.name))

    result = runner.invoke(app, ["rules"])

    assert _mentions(result, _HINT) == 1
    assert any(
        line.startswith(_WARNING) and "RuntimeError: this module was imported" in line
        for line in _stderr_lines(result)
    ), result.stderr


def test_a_stated_trust_warns_per_entry_point_and_gives_no_hint(site: FakeSite) -> None:
    _refused_pack(site)

    result = runner.invoke(app, ["rules", "--plugins", "builtins"])

    assert _mentions(result, _HINT) == 0
    warnings = [line for line in _stderr_lines(result) if line.startswith(_WARNING)]
    assert len(warnings) == 1
    assert "acme-scanner" in warnings[0]
    assert "acme-rules" in warnings[0]
