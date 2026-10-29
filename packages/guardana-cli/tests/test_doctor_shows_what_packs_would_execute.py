"""`doctor` names every third-party Guardana entry point, and what this run did with it.

The distributions here are real `.dist-info` directories read by the same metadata
finder a pip-installed pack goes through, and their modules leave a marker when
imported, so "listed without importing" is proven by a file that never appears.
"""

import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import EXPLODING_MODULE, MARKING_MODULE, FakeModule, FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import EVALUATOR_GROUP, RULE_GROUP, installed_entry_points
from guardana.core.plugins import BUILTIN_DISTRIBUTIONS, normalize_distribution
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_ENTRY_LINE = re.compile(r"^(guardana\.\S+) (\S+) → module (\S+): (.+)$")


def _lines(text: str) -> list[str]:
    return [" ".join(line.split()) for line in _ANSI.sub("", text).splitlines() if line.strip()]


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def _check_line(result: Result, name: str) -> str:
    """The line of the check called `name`, mark included."""
    matches = [line for line in _lines(result.stdout) if line[2:].startswith(f"{name}:")]
    assert len(matches) == 1, result.stdout
    return matches[0]


def _entries(result: Result) -> list[tuple[str, str, str, str]]:
    """Every `(group, entry point, module, state)` line doctor printed."""
    return [
        (match[1], match[2], match[3], match[4])
        for line in _lines(result.stdout)
        if (match := _ENTRY_LINE.match(line))
    ]


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _pack(
    site: FakeSite, name: str, *, body: str = MARKING_MODULE, entry_points: int = 1
) -> FakeModule:
    module = site.module(body)
    site.distribution(
        name, *((RULE_GROUP, f"{name}-ep{index}", module.name) for index in range(entry_points))
    )
    return module


def _profile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_default_lists_a_third_party_pack_as_refused_without_importing_it(
    site: FakeSite,
) -> None:
    module = _pack(site, "Acme_Rules", entry_points=2)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _check_line(result, "pack Acme_Rules 1.0").startswith("! ")
    assert _entries(result) == [
        (RULE_GROUP, "Acme_Rules-ep0", module.name, "refused"),
        (RULE_GROUP, "Acme_Rules-ep1", module.name, "refused"),
    ]
    assert not module.marker.exists()


def test_the_consequence_of_a_refusal_follows_the_profiles_gate(
    site: FakeSite, tmp_path: Path
) -> None:
    _pack(site, "Acme_Rules")
    gate_off = _profile(tmp_path, "name: t\nfail_on:\n  fail_on_error: false\n")

    on = runner.invoke(app, ["doctor"])
    off = runner.invoke(app, ["doctor", "--profile", str(gate_off)])

    refused_on = _plain(on.stdout)
    assert (
        "scan and probe exit 2, and monitor alerts every cycle, while these stay refused"
        in refused_on
    )
    assert "--plugins allowlist --allow-plugin Acme_Rules" in refused_on
    assert "plugins: {mode: allowlist, allow: [Acme_Rules]}" in refused_on
    assert _check_line(off, "refused packs").startswith("! ")
    assert "simply do not run" in _plain(off.stdout)
    assert "exit 2" not in _plain(off.stdout)


def test_doctors_refused_set_is_the_set_scan_records_as_discovery_errors(
    site: FakeSite, tmp_path: Path
) -> None:
    _pack(site, "acme-rules", entry_points=2)
    beta = site.module(MARKING_MODULE)
    site.distribution("beta-rules", (EVALUATOR_GROUP, "beta-judge", beta.name))
    model = tmp_path / "model"
    model.mkdir()
    saved = tmp_path / "run.json"

    doctor = runner.invoke(app, ["doctor"])
    scan = runner.invoke(app, ["scan", str(model), "--format", "json", "--output", str(saved)])

    assert scan.exit_code == ExitCode.INDETERMINATE, scan.output
    refused_by_doctor = sorted(name for _, name, _, state in _entries(doctor) if state == "refused")
    discovery_errors = sorted(
        error["source"]
        for error in json.loads(saved.read_text(encoding="utf-8"))["errors"]
        if error["stage"] == "discovery"
    )
    assert refused_by_doctor == ["acme-rules-ep0", "acme-rules-ep1", "beta-judge"]
    assert refused_by_doctor == discovery_errors


def test_an_allowlisted_pack_is_listed_as_loaded(site: FakeSite) -> None:
    """The control for the refusal tests: the same pack, admitted, is imported."""
    module = _pack(site, "acme-rules")

    result = runner.invoke(
        app, ["doctor", "--plugins", "allowlist", "--allow-plugin", "Acme.Rules"]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [(RULE_GROUP, "acme-rules-ep0", module.name, "loaded")]
    assert module.marker.exists()


def test_an_admitted_pack_that_fails_to_import_is_a_failure(site: FakeSite) -> None:
    module = _pack(site, "boom-rules", body=EXPLODING_MODULE)

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _check_line(result, "pack boom-rules 1.0").startswith("✖ ")
    [(_, _, _, state)] = _entries(result)
    assert state == "failed to import (RuntimeError: this module was imported)"
    assert "1 problem(s)" in _plain(result.stdout)
    assert module.marker.exists()


def test_a_failure_is_pinned_on_its_own_entry_point_when_another_group_shares_its_name(
    site: FakeSite,
) -> None:
    calm = site.module(MARKING_MODULE)
    boom = site.module(EXPLODING_MODULE)
    site.distribution(
        "Acme_Rules", (RULE_GROUP, "acme", calm.name), (EVALUATOR_GROUP, "acme", boom.name)
    )

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _check_line(result, "pack Acme_Rules 1.0").startswith("✖ ")
    assert _entries(result) == [
        (RULE_GROUP, "acme", calm.name, "loaded"),
        (
            EVALUATOR_GROUP,
            "acme",
            boom.name,
            "failed to import (RuntimeError: this module was imported)",
        ),
    ]
    assert "plugin acme:" not in _plain(result.stdout), "reported once, on its pack"
    assert "1 problem(s)" in _plain(result.stdout)


def test_a_failure_whose_name_a_built_in_shares_is_pinned_on_the_pack(site: FakeSite) -> None:
    module = site.module(EXPLODING_MODULE)
    site.distribution("boom-rules", (RULE_GROUP, "builtin", module.name))

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _check_line(result, "pack boom-rules 1.0").startswith("✖ ")
    [(_, _, _, state)] = _entries(result)
    assert state == "failed to import (RuntimeError: this module was imported)"
    assert "plugin builtin:" not in _plain(result.stdout)
    assert _check_line(result, "rules discovered").startswith("✓ "), "the built-ins still load"
    assert "1 problem(s)" in _plain(result.stdout)


def test_a_failure_whose_name_two_packs_share_is_pinned_on_the_one_that_failed(
    site: FakeSite,
) -> None:
    site.distribution("boom-rules", (RULE_GROUP, "shared", site.module(EXPLODING_MODULE).name))
    site.distribution("calm-rules", (RULE_GROUP, "shared", site.module(MARKING_MODULE).name))

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _check_line(result, "pack boom-rules 1.0").startswith("✖ ")
    assert _check_line(result, "pack calm-rules 1.0").startswith("✓ ")
    assert sorted(state.split(" (", 1)[0] for *_, state in _entries(result)) == [
        "failed to import",
        "loaded",
    ]
    assert "1 problem(s)" in _plain(result.stdout)


def test_a_refusal_alone_does_not_make_doctor_fail(site: FakeSite) -> None:
    module = _pack(site, "boom-rules", body=EXPLODING_MODULE)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "0 problem(s)" in _plain(result.stdout)
    assert not module.marker.exists()


def test_without_third_party_entry_points_doctor_says_so_and_counts_the_built_ins() -> None:
    builtins = {normalize_distribution(name) for name in BUILTIN_DISTRIBUTIONS}
    count = sum(
        1
        for entry_point in installed_entry_points()
        if entry_point.distribution is not None
        and normalize_distribution(entry_point.distribution) in builtins
    )

    result = runner.invoke(app, ["doctor"])

    line = _check_line(result, "installed packs")
    assert line.startswith("✓ ")
    assert "no third-party Guardana entry points are installed" in line
    assert f"{count} built-in Guardana entry point(s)" in line
    assert _entries(result) == []


def test_a_profile_that_widens_trust_is_warned_about(tmp_path: Path) -> None:
    widening = _profile(tmp_path, "name: t\nplugins:\n  mode: all\n")

    result = runner.invoke(app, ["doctor", "--profile", str(widening)])

    line = _check_line(result, "profile plugins")
    assert line.startswith("! ")
    assert "pass --plugins builtins as a flag" in line


@pytest.mark.parametrize("body", ["name: t\n", "name: t\nplugins:\n  mode: builtins\n"])
def test_a_profile_that_keeps_builtins_is_not_warned_about(tmp_path: Path, body: str) -> None:
    result = runner.invoke(app, ["doctor", "--profile", str(_profile(tmp_path, body))])

    assert "profile plugins" not in _plain(result.stdout)


def test_the_builtins_flag_outranks_a_profile_that_trusts_everything(
    site: FakeSite, tmp_path: Path
) -> None:
    module = _pack(site, "acme-rules")
    widening = _profile(tmp_path, "name: t\nplugins:\n  mode: all\n")

    result = runner.invoke(app, ["doctor", "--profile", str(widening), "--plugins", "builtins"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [(RULE_GROUP, "acme-rules-ep0", module.name, "refused")]
    assert not module.marker.exists()


def test_disabled_trust_says_the_built_ins_were_refused_too() -> None:
    result = runner.invoke(app, ["doctor", "--plugins", "disabled"])

    line = _check_line(result, "plugin trust")
    assert line.startswith("! ")
    assert "built-in Guardana entry point(s) refused" in line
