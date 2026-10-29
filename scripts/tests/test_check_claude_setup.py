"""The setup gate: the agent instructions still describe this repository.

The positive case runs against the real tree. Every other case builds a small
broken tree and expects the gate to name the drift — a gate that only ever says
"in sync" has never been shown to notice anything.
"""

import json
import subprocess
from pathlib import Path

import pytest

import check_claude_setup

SKILL = "---\nname: {name}\ndescription: Does a thing.\n---\n# Body\n"
AGENT = "---\nname: {name}\ndescription: Looks things up.\nmodel: {model}\n---\nBody.\n"
GUARD = 'python3 "${CLAUDE_PROJECT_DIR:-.}/scripts/guard_hook.py"'


def _settings(
    matcher: str = "Bash|Write|Edit|MultiEdit|NotebookEdit", event: str = "PreToolUse"
) -> str:
    entry = {"matcher": matcher, "hooks": [{"type": "command", "command": GUARD}]}
    return json.dumps({"hooks": {event: [entry]}})


def _tree(root: Path, *, claude_md: str = "# Guardana\n") -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # noqa: S603, S607
    (root / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text(_settings(), encoding="utf-8")
    (root / ".claude" / "skills" / "work").mkdir(parents=True)
    (root / ".claude" / "skills" / "work" / "SKILL.md").write_text(
        SKILL.format(name="work"), encoding="utf-8"
    )
    (root / ".claude" / "agents").mkdir()
    (root / ".claude" / "agents" / "scout.md").write_text(
        AGENT.format(name="scout", model="haiku"), encoding="utf-8"
    )
    (root / ".claude" / "rules").mkdir()
    (root / "scripts").mkdir()
    (root / "scripts" / "x.py").write_text("", encoding="utf-8")
    (root / "scripts" / "guard_hook.py").write_text("", encoding="utf-8")
    (root / ".claude" / "rules" / "scripts.md").write_text(
        '---\npaths:\n  - "scripts/**"\n---\n# Scripts\n', encoding="utf-8"
    )


def _problems(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], root: Path
) -> str:
    monkeypatch.setattr(check_claude_setup, "ROOT", root)
    assert check_claude_setup.main() == 1
    return capsys.readouterr().out


def test_the_real_setup_is_in_sync(capsys: pytest.CaptureFixture[str]) -> None:
    assert check_claude_setup.main() == 0
    assert "agent setup in sync" in capsys.readouterr().out


def test_a_clean_tree_passes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    monkeypatch.setattr(check_claude_setup, "ROOT", tmp_path)
    assert check_claude_setup.main() == 0
    assert "in sync" in capsys.readouterr().out


def test_a_rule_without_paths_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "rules" / "always.md").write_text(
        "---\ndescription: x\n---\n# Always\n", encoding="utf-8"
    )
    assert "always.md: a rule without `paths`" in _problems(monkeypatch, capsys, tmp_path)


def test_a_glob_that_matches_nothing_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "rules" / "gone.md").write_text(
        '---\npaths:\n  - "apps/{api,ui}/**"\n---\n# Gone\n', encoding="utf-8"
    )
    assert "glob matches no file: apps/{api,ui}/**" in _problems(monkeypatch, capsys, tmp_path)


def test_a_quoted_path_that_does_not_exist_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path, claude_md="# Guardana\n\nRead `docs/nowhere.md` and `scripts/x.py`.\n")
    out = _problems(monkeypatch, capsys, tmp_path)
    assert "CLAUDE.md: points at a path that does not exist: docs/nowhere.md" in out
    assert "scripts/x.py" not in out


def test_placeholders_are_not_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path, claude_md="# G\n\n`docs/usage-<command>.md`, `packages/*/tests/**`, `docs/…`\n")
    monkeypatch.setattr(check_claude_setup, "ROOT", tmp_path)
    assert check_claude_setup.main() == 0


def test_the_line_budget_is_enforced(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path, claude_md="# Guardana\n" * (check_claude_setup.CLAUDE_MD_MAX_LINES + 1))
    assert "CLAUDE.md is 151 lines (budget 150)" in _problems(monkeypatch, capsys, tmp_path)


def test_an_agent_on_a_model_outside_the_aliases_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "agents" / "big.md").write_text(
        AGENT.format(name="big", model="some-preview-model"), encoding="utf-8"
    )
    out = _problems(monkeypatch, capsys, tmp_path)
    assert "big.md: model 'some-preview-model' is not one of" in out


def _exclude(root: Path, *lines: str) -> None:
    exclude = root / ".git" / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    exclude.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_a_private_skill_named_exactly_in_info_exclude_is_left_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    private = tmp_path / ".claude" / "skills" / "mine"
    private.mkdir()
    (private / "SKILL.md").write_text(
        "no frontmatter, points at `scripts/gone.py`\n", encoding="utf-8"
    )
    _exclude(tmp_path, ".claude/skills/mine/")
    monkeypatch.setattr(check_claude_setup, "ROOT", tmp_path)
    assert check_claude_setup.main() == 0
    assert "in sync" in capsys.readouterr().out


def test_a_wildcard_in_info_exclude_hides_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "rules" / "local.md").write_text(
        '---\npaths:\n  - "scripts/**"\n---\n# Local\n', encoding="utf-8"
    )
    _exclude(tmp_path, ".claude/rules/*.md")
    out = _problems(monkeypatch, capsys, tmp_path)
    assert ".claude/rules/local.md: gitignored" in out


def test_a_skill_whose_name_disagrees_with_its_directory_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "skills" / "ship").mkdir()
    (tmp_path / ".claude" / "skills" / "ship" / "SKILL.md").write_text(
        SKILL.format(name="shipit"), encoding="utf-8"
    )
    assert "`name` is 'shipit', the file says 'ship'" in _problems(monkeypatch, capsys, tmp_path)


def test_a_skill_that_runs_as_a_missing_agent_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "skills" / "review").mkdir()
    (tmp_path / ".claude" / "skills" / "review" / "SKILL.md").write_text(
        "---\nname: review\ndescription: Reviews.\ncontext: fork\nagent: judge\n---\nBody.\n",
        encoding="utf-8",
    )
    assert "runs as agent 'judge', which does not exist" in _problems(monkeypatch, capsys, tmp_path)


def test_frontmatter_that_does_not_parse_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "agents" / "broken.md").write_text(
        "---\nname: broken\ndescription: has: a colon: in it [and\n---\n", encoding="utf-8"
    )
    assert "broken.md: frontmatter does not parse" in _problems(monkeypatch, capsys, tmp_path)


def test_a_hook_pointing_at_a_missing_script_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    settings = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": 'python3 "${CLAUDE_PROJECT_DIR:-.}/scripts/gone_hook.py"',
                        }
                    ],
                }
            ]
        }
    }
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    assert "hook points at a missing file: scripts/gone_hook.py" in _problems(
        monkeypatch, capsys, tmp_path
    )


def test_settings_without_the_guard_hook_are_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Empty settings are valid JSON and point at no missing file, and run no guard at all."""
    _tree(tmp_path)
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    out = _problems(monkeypatch, capsys, tmp_path)
    assert "no PreToolUse hook runs scripts/guard_hook.py" in out


def test_the_guard_wired_to_the_wrong_event_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "settings.json").write_text(
        _settings(event="PostToolUse"), encoding="utf-8"
    )
    assert "no PreToolUse hook runs scripts/guard_hook.py" in _problems(
        monkeypatch, capsys, tmp_path
    )


def test_a_guard_that_misses_a_tool_it_decides_on_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "settings.json").write_text(_settings("Bash|Edit"), encoding="utf-8")
    out = _problems(monkeypatch, capsys, tmp_path)
    assert "guard_hook.py never sees: MultiEdit, NotebookEdit, Write" in out


@pytest.mark.parametrize("matcher", ["*", "", "Bash|Write|Edit|MultiEdit|NotebookEdit"])
def test_a_guard_on_every_tool_it_decides_on_passes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    matcher: str,
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "settings.json").write_text(_settings(matcher), encoding="utf-8")
    monkeypatch.setattr(check_claude_setup, "ROOT", tmp_path)
    assert check_claude_setup.main() == 0
    assert "in sync" in capsys.readouterr().out


def test_a_missing_settings_file_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "settings.json").unlink()
    assert ".claude/settings.json is missing" in _problems(monkeypatch, capsys, tmp_path)


def test_an_empty_kind_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "rules" / "scripts.md").unlink()
    assert "no rule matches .claude/rules/*.md" in _problems(monkeypatch, capsys, tmp_path)


def test_a_gitignored_file_under_claude_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A skill directory named like a build artifact vanished this way once, unseen by git."""
    _tree(tmp_path)
    (tmp_path / ".gitignore").write_text("build/\n", encoding="utf-8")
    (tmp_path / ".claude" / "skills" / "build").mkdir()
    (tmp_path / ".claude" / "skills" / "build" / "SKILL.md").write_text(
        SKILL.format(name="build"), encoding="utf-8"
    )
    out = _problems(monkeypatch, capsys, tmp_path)
    assert ".claude/skills/build/SKILL.md: gitignored" in out


def test_the_harness_local_files_are_not_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A live session's lock, local settings or worktree must not turn the gate red."""
    _tree(tmp_path)
    (tmp_path / ".gitignore").write_text(
        ".claude/scheduled_tasks.lock\n.claude/settings.local.json\n.claude/worktrees/\n",
        encoding="utf-8",
    )
    (tmp_path / ".claude" / "scheduled_tasks.lock").write_text("{}", encoding="utf-8")
    (tmp_path / ".claude" / "settings.local.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".claude" / "worktrees" / "lane").mkdir(parents=True)
    (tmp_path / ".claude" / "worktrees" / "lane" / "x.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(check_claude_setup, "ROOT", tmp_path)
    assert check_claude_setup.main() == 0
    assert "in sync" in capsys.readouterr().out


def test_a_file_named_like_a_harness_file_elsewhere_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".gitignore").write_text(
        "*.lock\nworktrees/\nworktrees2/\n*.orig\n", encoding="utf-8"
    )
    (tmp_path / ".claude" / "scheduled_tasks.lock").write_text("{}", encoding="utf-8")
    (tmp_path / ".claude" / "settings.local.json.orig").write_text("{}", encoding="utf-8")
    (tmp_path / ".claude" / "worktrees2").mkdir()
    (tmp_path / ".claude" / "worktrees2" / "x").write_text("", encoding="utf-8")
    (tmp_path / ".claude" / "skills" / "work" / "scheduled_tasks.lock").write_text(
        "{}", encoding="utf-8"
    )
    (tmp_path / ".claude" / "skills" / "worktrees").mkdir()
    (tmp_path / ".claude" / "skills" / "worktrees" / "SKILL.md").write_text(
        SKILL.format(name="worktrees"), encoding="utf-8"
    )
    out = _problems(monkeypatch, capsys, tmp_path)
    assert ".claude/skills/work/scheduled_tasks.lock: gitignored" in out
    assert ".claude/skills/worktrees/SKILL.md: gitignored" in out
    assert ".claude/settings.local.json.orig: gitignored" in out
    assert ".claude/worktrees2/x: gitignored" in out
    assert ".claude/scheduled_tasks.lock:" not in out


def test_a_path_git_would_quote_is_matched_unquoted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".gitignore").write_text(".claude/worktrees/\n", encoding="utf-8")
    (tmp_path / ".claude" / "worktrees").mkdir()
    (tmp_path / ".claude" / "worktrees" / "\u00e9.txt").write_text("", encoding="utf-8")
    monkeypatch.setattr(check_claude_setup, "ROOT", tmp_path)
    assert check_claude_setup.main() == 0
    assert "in sync" in capsys.readouterr().out


def test_a_tracked_skill_named_in_info_exclude_is_still_checked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path)
    (tmp_path / ".claude" / "skills" / "work" / "SKILL.md").write_text(
        "no frontmatter\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", ".claude"], check=True)  # noqa: S603, S607
    _exclude(tmp_path, ".claude/skills/work/")
    assert "work/SKILL.md: frontmatter does not parse" in _problems(monkeypatch, capsys, tmp_path)


def test_principles_that_differ_between_agents_and_people_are_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _tree(tmp_path, claude_md="# Guardana\n\n## Product principles — x\n\n1. One.\n2. Two.\n")
    (tmp_path / "CONTRIBUTING.md").write_text(
        "# Contributing\n\n## Principles\n\n1. One.\n", encoding="utf-8"
    )
    assert "Principles differ" in _problems(monkeypatch, capsys, tmp_path)
