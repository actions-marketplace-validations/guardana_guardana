#!/usr/bin/env python3
"""Gate: the agent setup under .claude/ still describes this repository.

An instruction that points at a file that moved, or a path-scoped rule whose
glob matches nothing, fails silently: the agent simply never sees it.

    uv run python scripts/check_claude_setup.py

Checks: frontmatter parses; skills and agents have a description and a name
matching their file; a skill's `agent:` exists; every rule has `paths` and every
glob matches a file; repo paths quoted in CLAUDE.md, rules, skills and agents
exist; the hook commands in settings.json point at files, and a PreToolUse hook
runs scripts/guard_hook.py on every tool it decides on; no agent is
configured on a model family this repository never uses; nothing under .claude/
is gitignored except the harness's machine-local state; CLAUDE.md stays inside
its line budget. Exit 0 clean, 1 findings.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CLAUDE_MD_MAX_LINES = 150
# The model aliases an agent may name; a full model id would pin one release for everybody.
AGENT_MODELS = frozenset({"haiku", "sonnet", "opus", "inherit"})
# A quoted token is checked as a path only when it starts in a directory this repo owns.
PATH_ROOTS = (
    "packages/",
    "scripts/",
    "docs/",
    "examples/",
    "deploy/",
    "site/",
    "schemas/",
    ".claude/",
    ".github/",
)
QUOTED = re.compile(r"`([^`\s]+)`")
PLACEHOLDER = re.compile(r"[<>{}*$…]|\.\.\.")
HOOK_PATH = re.compile(r"CLAUDE_PROJECT_DIR[^\"]*?/(scripts/[\w./-]+)")
GUARD_HOOK = "scripts/guard_hook.py"
# The tools `guard_hook.py` decides on; a matcher that misses one leaves that tool unguarded.
GUARDED_TOOLS = ("Bash", "Edit", "MultiEdit", "NotebookEdit", "Write")
# Written by the harness while sessions run and ignored on purpose; a trailing slash is a directory.
HARNESS_LOCAL = (
    ".claude/scheduled_tasks.lock",
    ".claude/settings.local.json",
    ".claude/worktrees/",
)


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("no frontmatter")
    loaded: object = yaml.safe_load(text.split("---\n", 2)[1])
    if not isinstance(loaded, dict):
        raise TypeError("frontmatter is not a mapping")
    return {str(key): value for key, value in loaded.items()}


def _expand(pattern: str) -> list[str]:
    match = re.search(r"\{([^{}]*)\}", pattern)
    if not match:
        return [pattern]
    head, tail = pattern[: match.start()], pattern[match.end() :]
    return [p for option in match.group(1).split(",") for p in _expand(head + option + tail)]


def _quoted_paths(text: str) -> set[str]:
    found = set()
    for token in QUOTED.findall(text):
        cleaned = token.rstrip(".,;:)").split("::")[0].split("#")[0]
        if cleaned.startswith(PATH_ROOTS) and not PLACEHOLDER.search(cleaned):
            found.add(re.sub(r":\d+(-\d+)?$", "", cleaned))
    return found


def _check_rule(name: str, meta: dict[str, object], problems: list[str]) -> None:
    globs = meta.get("paths")
    if not isinstance(globs, list) or not globs:
        problems.append(f"{name}: a rule without `paths` loads in every session")
        return
    problems.extend(
        f"{name}: glob matches no file: {glob}"
        for glob in globs
        if not any(any(ROOT.glob(option)) for option in _expand(str(glob)))
    )


def _check_named(
    kind: str, path: Path, name: str, meta: dict[str, object], problems: list[str]
) -> None:
    expected = path.parent.name if kind == "skill" else path.stem
    if meta.get("name") != expected:
        problems.append(f"{name}: `name` is {meta.get('name')!r}, the file says {expected!r}")
    description = meta.get("description")
    if not isinstance(description, str) or not description.strip():
        problems.append(f"{name}: missing description")
    model = str(meta.get("model", "inherit")).lower()
    if kind == "agent" and model not in AGENT_MODELS:
        problems.append(f"{name}: model {model!r} is not one of {sorted(AGENT_MODELS)}")
    agent = meta.get("agent")
    if kind == "skill" and agent and not (ROOT / ".claude" / "agents" / f"{agent}.md").exists():
        problems.append(f"{name}: runs as agent {agent!r}, which does not exist")


def _check_hooks(problems: list[str]) -> None:
    settings = ROOT / ".claude" / "settings.json"
    if not settings.exists():
        problems.append(".claude/settings.json is missing: no hooks run for anybody")
        return
    text = settings.read_text(encoding="utf-8")
    try:
        loaded: object = json.loads(text)
    except json.JSONDecodeError as exc:
        problems.append(f".claude/settings.json does not parse: {exc}")
        return
    problems.extend(
        f".claude/settings.json: hook points at a missing file: {hook}"
        for hook in HOOK_PATH.findall(text)
        if not (ROOT / hook).exists()
    )
    _check_guard(loaded, problems)


def _check_guard(settings: object, problems: list[str]) -> None:
    """Require a PreToolUse hook running the guard on every tool the guard decides on.

    Settings without it still parse and point at no missing file, and run no guard.
    """
    matchers = [
        str(entry.get("matcher") or "")
        for entry in _items(_field(_field(settings, "hooks"), "PreToolUse"))
        if any(
            GUARD_HOOK in str(_field(hook, "command")) for hook in _items(_field(entry, "hooks"))
        )
    ]
    if not matchers:
        problems.append(f".claude/settings.json: no PreToolUse hook runs {GUARD_HOOK}")
        return
    unseen = [tool for tool in GUARDED_TOOLS if not any(_matches(m, tool) for m in matchers)]
    if unseen:
        problems.append(f".claude/settings.json: guard_hook.py never sees: {', '.join(unseen)}")


def _field(value: object, key: str) -> object:
    return value.get(key) if isinstance(value, dict) else None


def _items(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _matches(matcher: str, tool: str) -> bool:
    """Read a hook matcher the way the harness does: empty or `*` is every tool, else a regex."""
    if matcher in {"", "*"}:
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return False


def _check_ignored(problems: list[str]) -> None:
    """Name every gitignored file under .claude/ but the harness's own: a clone never gets it."""
    try:
        done = subprocess.run(
            [  # noqa: S607
                "git",
                "ls-files",
                "-z",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--",
                ".claude",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        problems.append(f"could not ask git which files under .claude/ are ignored: {exc}")
        return
    private = _private_overlay()
    problems.extend(
        f"{line}: gitignored, so it is not in the repository"
        for line in done.stdout.split("\0")
        if line and not _harness_local(line) and not _within(line, private)
    )


def _private_overlay() -> tuple[str, ...]:
    """Paths this clone's owner keeps out of the repository, named exactly in `info/exclude`.

    Only an exact path counts: a wildcard there would let a local pattern hide a file the
    shared setup needs, and the check runs in CI on a clone without any such file.
    """
    try:
        done = subprocess.run(
            ["git", "rev-parse", "--git-path", "info/exclude"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        lines = (ROOT / done.stdout.strip()).read_text(encoding="utf-8").splitlines()
    except (OSError, subprocess.SubprocessError):
        return ()
    return tuple(
        line.strip().lstrip("/")
        for line in lines
        if line.strip()
        and not line.lstrip().startswith(("#", "!"))
        and not any(char in line for char in "*?[")
    )


def _tracked() -> frozenset[str]:
    try:
        done = subprocess.run(
            ["git", "ls-files", "-z", "--", ".claude"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(line for line in done.stdout.split("\0") if line)


def _principles(text: str, heading: str) -> list[str]:
    """Return the numbered list under the `##` heading that starts with `heading`."""
    _, found, after = text.partition(f"\n## {heading}")
    if not found:
        return []
    body = after.split("\n## ", 1)[0]
    return [line.split(". ", 1)[1] for line in body.splitlines() if re.match(r"\d+\. ", line)]


def _check_principles(problems: list[str]) -> None:
    """Require CONTRIBUTING.md to state the principles CLAUDE.md gives every agent."""
    contributing = ROOT / "CONTRIBUTING.md"
    if not contributing.exists():
        return
    agents = _principles((ROOT / "CLAUDE.md").read_text(encoding="utf-8"), "Product principles")
    people = _principles(contributing.read_text(encoding="utf-8"), "Principles")
    if agents != people:
        problems.append(
            "CLAUDE.md § Product principles and CONTRIBUTING.md § Principles differ: "
            "change both together"
        )


def _within(path: str, entries: tuple[str, ...]) -> bool:
    return any(
        path == entry.rstrip("/") or (entry.endswith("/") and path.startswith(entry))
        for entry in entries
    )


def _harness_local(path: str) -> bool:
    return any(
        path == entry or (entry.endswith("/") and path.startswith(entry)) for entry in HARNESS_LOCAL
    )


def main() -> int:
    """Run every check and print the drift, if any."""
    problems: list[str] = []
    documents = [ROOT / "CLAUDE.md"]
    private = _private_overlay()
    tracked = _tracked()

    for kind, pattern in (
        ("skill", "skills/*/SKILL.md"),
        ("agent", "agents/*.md"),
        ("rule", "rules/*.md"),
    ):
        found = [
            path
            for path in sorted((ROOT / ".claude").glob(pattern))
            if path.relative_to(ROOT).as_posix() in tracked
            or not _within(path.relative_to(ROOT).as_posix(), private)
        ]
        if not found:
            problems.append(f"no {kind} matches .claude/{pattern}: the directory moved or is empty")
        for path in found:
            documents.append(path)
            name = path.relative_to(ROOT).as_posix()
            try:
                meta = _frontmatter(path)
            except (ValueError, TypeError, yaml.YAMLError) as exc:
                problems.append(f"{name}: frontmatter does not parse ({str(exc).splitlines()[0]})")
                continue
            if kind == "rule":
                _check_rule(name, meta, problems)
            else:
                _check_named(kind, path, name, meta, problems)

    for path in documents:
        name = path.relative_to(ROOT).as_posix()
        problems.extend(
            f"{name}: points at a path that does not exist: {quoted}"
            for quoted in sorted(_quoted_paths(path.read_text(encoding="utf-8")))
            if not (ROOT / quoted).exists()
        )

    _check_hooks(problems)
    _check_ignored(problems)
    _check_principles(problems)

    lines = len((ROOT / "CLAUDE.md").read_text(encoding="utf-8").splitlines())
    if lines > CLAUDE_MD_MAX_LINES:
        problems.append(
            f"CLAUDE.md is {lines} lines (budget {CLAUDE_MD_MAX_LINES}): it loads into every "
            "session and subagent — move detail to a rule or a skill"
        )

    if problems:
        print(f"agent setup has drifted ({len(problems)}):")
        print("\n".join(f"  {problem}" for problem in problems))
        return 1
    print(f"agent setup in sync: {len(documents)} files, CLAUDE.md {lines} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
