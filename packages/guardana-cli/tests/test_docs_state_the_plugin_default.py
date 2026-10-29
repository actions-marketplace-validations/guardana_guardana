"""Every page that states the default plugin trust states the one the CLI resolves to.

A default that moved while one usage table kept the old value tells a reader the
opposite of what their run does, about the one setting that decides what code a
run imports.
"""

import re
from pathlib import Path

import pytest
from guardana.cli._plugins import DEFAULT_MODE
from guardana.core.plugins import PluginMode

_REPO = Path(__file__).resolve().parents[3]
_MODES = "|".join(str(mode) for mode in PluginMode)
_TABLE_ROW = re.compile(rf"^\|\s*`--plugins(?:\\\||[^|])*\|\s*`({_MODES})`[^|\n]*\|", re.MULTILINE)
_PROSE = re.compile(
    rf"`(?:--plugins )?({_MODES})` is (?:still )?the default"
    rf"|defaults? (?:is|to) `(?:--plugins )?({_MODES})`"
    rf"|`({_MODES})` unless the flag",
)
_OPTION_ROW = re.compile(r"^\|[^|\n]*`--plugins", re.MULTILINE)


def _pages() -> list[Path]:
    pages = [_REPO / "README.md", _REPO / "SECURITY.md", _REPO / "FEATURES.md"]
    for page in sorted((_REPO / "docs").rglob("*.md")):
        relative = page.relative_to(_REPO / "docs").parts
        if relative[0] not in {"design", "work", "generated"}:
            pages.append(page)
    return pages


def _stated_defaults(text: str) -> list[str]:
    stated = [match.group(1) for match in _TABLE_ROW.finditer(text)]
    for line in text.splitlines():
        if "plugin" not in line.lower():
            continue
        stated.extend(next(g for g in match.groups() if g) for match in _PROSE.finditer(line))
    return stated


@pytest.mark.parametrize("page", _pages(), ids=lambda page: page.relative_to(_REPO).as_posix())
def test_a_page_states_the_default_the_cli_resolves_to(page: Path) -> None:
    wrong = [
        mode for mode in _stated_defaults(page.read_text(encoding="utf-8")) if mode != DEFAULT_MODE
    ]

    assert not wrong, f"{page.name} states the --plugins default as {wrong}; it is {DEFAULT_MODE}"


def test_every_usage_page_with_a_plugins_option_states_its_default() -> None:
    pages = sorted((_REPO / "docs").glob("usage-*.md"))
    silent = [
        page.name
        for page in pages
        if _OPTION_ROW.search(text := page.read_text(encoding="utf-8"))
        and not _stated_defaults(text)
    ]

    assert len([p for p in pages if _OPTION_ROW.search(p.read_text(encoding="utf-8"))]) >= 10
    assert not silent, f"usage page(s) with a --plugins option that state no default: {silent}"


def test_the_patterns_catch_each_way_a_page_states_the_default() -> None:
    assert _stated_defaults("| `--plugins [all\\|builtins]` | `all` | which plugins |") == ["all"]
    assert _stated_defaults("| `--plugins [all\\|builtins]` | `all`, or the profile's | x |") == [
        "all"
    ]
    assert _stated_defaults("Plugin trust: `--plugins all` is still the default.") == ["all"]
    assert _stated_defaults("Which installed plugins to load; defaults to `all`.") == ["all"]
    assert _stated_defaults("The default is `builtins` for every plugin.") == ["builtins"]
    assert _stated_defaults("Plugin trust is `all` unless the flag says so.") == ["all"]
    assert _stated_defaults("`fail_on_error` defaults to `true`.") == []
