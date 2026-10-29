"""`doctor` lists installed formats and reporters from metadata, and never imports one.

An output is imported only when a run selects it, so what doctor says about one is
decided from its entry point and the plugin trust: whether selecting it would be
admitted, refused, or impossible. Each fake module leaves a marker when imported, and
both the marker and `sys.modules` prove doctor read metadata only.
"""

import re
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import MARKING_MODULE, FakeModule, FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import RENDERER_GROUP, REPORTER_GROUP, RULE_GROUP
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_ENTRY_LINE = re.compile(r"^(guardana\.\S+) (\S+) → module (\S+): (.+)$")


def _lines(text: str) -> list[str]:
    return [" ".join(line.split()) for line in _ANSI.sub("", text).splitlines() if line.strip()]


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def _check_lines(result: Result, name: str) -> list[str]:
    """Every line of the checks called `name`, mark included."""
    return [line for line in _lines(result.stdout) if line[2:].startswith(f"{name}:")]


def _check_line(result: Result, name: str) -> str:
    matches = _check_lines(result, name)
    assert len(matches) == 1, result.stdout
    return matches[0]


def _entries(result: Result) -> list[tuple[str, str, str, str]]:
    """Every `(group, entry point, module, state)` line doctor printed."""
    return [
        (match[1], match[2], match[3], match[4])
        for line in _lines(result.stdout)
        if (match := _ENTRY_LINE.match(line))
    ]


def _not_imported(module: FakeModule) -> bool:
    return not module.marker.exists() and module.name not in sys.modules


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _outputs(site: FakeSite, name: str = "acme-outputs") -> tuple[FakeModule, FakeModule]:
    table = site.module(MARKING_MODULE)
    hook = site.module(MARKING_MODULE)
    site.distribution(
        name, (RENDERER_GROUP, "acme-table", table.name), (REPORTER_GROUP, "acme-hook", hook.name)
    )
    return table, hook


def test_under_the_default_an_output_only_pack_is_refused_if_selected_and_not_imported(
    site: FakeSite,
) -> None:
    table, hook = _outputs(site)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [
        (
            RENDERER_GROUP,
            "acme-table",
            table.name,
            "refused if selected under plugin trust builtins",
        ),
        (REPORTER_GROUP, "acme-hook", hook.name, "refused if selected under plugin trust builtins"),
    ]
    block = _check_line(result, "pack acme-outputs 1.0")
    assert block.startswith("✓ ")
    assert "2 output entry point(s) — 2 refused if selected" in block
    assert "0 Guardana entry point(s)" not in block
    assert "no third-party Guardana entry points are installed" not in _plain(result.stdout)
    assert "refused packs" not in _plain(result.stdout), "a run refuses nothing it never selects"
    assert _not_imported(table)
    assert _not_imported(hook)


def test_an_allowlisted_output_is_imported_only_when_selected(site: FakeSite) -> None:
    table, hook = _outputs(site)

    result = runner.invoke(
        app, ["doctor", "--plugins", "allowlist", "--allow-plugin", "acme-outputs"]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [
        (RENDERER_GROUP, "acme-table", table.name, "imported only when selected"),
        (REPORTER_GROUP, "acme-hook", hook.name, "imported only when selected"),
    ]
    assert _check_line(result, "pack acme-outputs 1.0").startswith("✓ ")
    assert "plugins.allow acme-outputs" not in _plain(result.stdout), "it does register outputs"
    assert _not_imported(table)
    assert _not_imported(hook)


def test_disabled_trust_names_itself_in_the_refusal(site: FakeSite) -> None:
    table, _ = _outputs(site)

    result = runner.invoke(app, ["doctor", "--plugins", "disabled"])

    assert (
        RENDERER_GROUP,
        "acme-table",
        table.name,
        "refused if selected under plugin trust disabled",
    ) in _entries(result)
    assert _not_imported(table)


def test_a_name_two_distributions_install_is_its_own_warning(site: FakeSite) -> None:
    first = site.module(MARKING_MODULE)
    second = site.module(MARKING_MODULE)
    site.distribution("acme-a", (RENDERER_GROUP, "acme-table", first.name))
    site.distribution("acme-b", (RENDERER_GROUP, "acme-table", second.name), version="2.0")

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _check_line(result, "output collision") == (
        "! output collision: the format acme-table is installed by 2 distributions "
        "(acme-a 1.0, acme-b 2.0); selecting it is refused"
    )
    assert [state for *_, state in _entries(result)] == [
        "never selectable: name installed by 2 distributions",
        "never selectable: name installed by 2 distributions",
    ]
    assert _check_line(result, "pack acme-a 1.0").startswith("! ")
    assert _check_line(result, "pack acme-b 2.0").startswith("! ")
    assert _not_imported(first)
    assert _not_imported(second)


def test_a_reporter_collision_is_named_as_a_reporter(site: FakeSite) -> None:
    site.distribution("acme-a", (REPORTER_GROUP, "acme-hook", site.module(MARKING_MODULE).name))
    site.distribution("acme-b", (REPORTER_GROUP, "acme-hook", site.module(MARKING_MODULE).name))

    result = runner.invoke(app, ["doctor"])

    assert _check_line(result, "output collision") == (
        "! output collision: the reporter acme-hook is installed by 2 distributions "
        "(acme-a 1.0, acme-b 1.0); selecting it is refused"
    )


def test_a_format_and_a_reporter_may_share_a_name(site: FakeSite) -> None:
    site.distribution("acme-a", (RENDERER_GROUP, "acme", site.module(MARKING_MODULE).name))
    site.distribution("acme-b", (REPORTER_GROUP, "acme", site.module(MARKING_MODULE).name))

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert _check_lines(result, "output collision") == []
    assert [state for *_, state in _entries(result)] == ["imported only when selected"] * 2


@pytest.mark.parametrize(
    ("group", "name", "reason"),
    [
        (RENDERER_GROUP, "json", "reserved name"),
        (RENDERER_GROUP, "guardana-table", "reserved name"),
        (REPORTER_GROUP, "https", "reserved name"),
        (RENDERER_GROUP, "Acme_Table", "invalid name"),
        (REPORTER_GROUP, "a" * 41, "invalid name"),
    ],
)
def test_an_output_that_can_never_be_selected_is_a_warning_and_not_imported(
    site: FakeSite, group: str, name: str, reason: str
) -> None:
    module = site.module(MARKING_MODULE)
    site.distribution("acme-outputs", (group, name, module.name))

    result = runner.invoke(app, ["doctor", "--plugins", "all"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [(group, name, module.name, f"never selectable: {reason}")]
    block = _check_line(result, "pack acme-outputs 1.0")
    assert block.startswith("! ")
    assert "1 never selectable" in block
    assert _not_imported(module)


def test_a_reserved_name_two_distributions_install_is_not_a_collision(site: FakeSite) -> None:
    site.distribution("acme-a", (RENDERER_GROUP, "json", site.module(MARKING_MODULE).name))
    site.distribution("acme-b", (RENDERER_GROUP, "json", site.module(MARKING_MODULE).name))

    result = runner.invoke(app, ["doctor"])

    assert _check_lines(result, "output collision") == []
    assert [state for *_, state in _entries(result)] == ["never selectable: reserved name"] * 2


def test_a_mixed_pack_lists_its_outputs_under_its_rules_and_only_rules_drive_the_consequence(
    site: FakeSite,
) -> None:
    rules = site.module(MARKING_MODULE)
    table = site.module(MARKING_MODULE)
    site.distribution(
        "acme-pack",
        (RULE_GROUP, "acme-rules", rules.name),
        (RENDERER_GROUP, "acme-table", table.name),
    )

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [
        (RULE_GROUP, "acme-rules", rules.name, "refused"),
        (
            RENDERER_GROUP,
            "acme-table",
            table.name,
            "refused if selected under plugin trust builtins",
        ),
    ]
    block = _check_line(result, "pack acme-pack 1.0")
    assert block.startswith("! ")
    assert (
        "1 Guardana entry point(s) — 1 refused; 1 output entry point(s) — 1 refused if selected"
        in block
    )
    assert _check_line(result, "refused packs").startswith("! ")
    assert "--plugins allowlist --allow-plugin acme-pack" in _plain(result.stdout)
    assert _not_imported(rules)
    assert _not_imported(table)


def test_an_admitted_mixed_pack_loads_its_rules_and_still_does_not_import_its_outputs(
    site: FakeSite,
) -> None:
    rules = site.module(MARKING_MODULE)
    table = site.module(MARKING_MODULE)
    site.distribution(
        "acme-pack",
        (RULE_GROUP, "acme-rules", rules.name),
        (RENDERER_GROUP, "acme-table", table.name),
    )

    result = runner.invoke(app, ["doctor", "--plugins", "allowlist", "--allow-plugin", "acme-pack"])

    assert result.exit_code == ExitCode.OK, result.output
    assert _entries(result) == [
        (RULE_GROUP, "acme-rules", rules.name, "loaded"),
        (RENDERER_GROUP, "acme-table", table.name, "imported only when selected"),
    ]
    assert "refused packs" not in _plain(result.stdout)
    assert rules.marker.exists(), "the control: an admitted rule is imported"
    assert _not_imported(table)


def test_output_states_never_make_doctor_fail(site: FakeSite) -> None:
    site.distribution("acme-a", (RENDERER_GROUP, "acme-table", site.module(MARKING_MODULE).name))
    site.distribution(
        "acme-b",
        (RENDERER_GROUP, "acme-table", site.module(MARKING_MODULE).name),
        (RENDERER_GROUP, "json", site.module(MARKING_MODULE).name),
        (REPORTER_GROUP, "Bad Name", site.module(MARKING_MODULE).name),
        (REPORTER_GROUP, "acme-hook", site.module(MARKING_MODULE).name),
    )

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "0 problem(s)" in _plain(result.stdout)
    assert not any(line.startswith("✖ ") for line in _lines(result.stdout))
