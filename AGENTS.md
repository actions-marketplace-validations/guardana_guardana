# AGENTS.md

Instructions for AI coding agents working in this repository, whatever the tool.

- The project's rules, commands, principles and protected contracts are in
  [`CLAUDE.md`](CLAUDE.md); they apply to every agent, not only Claude. Path-scoped notes
  for the code you are editing are in [`.claude/rules/`](.claude/rules/).
- Principles and the contribution process, for people and agents alike:
  [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Run `scripts/ci_local.sh --quiet` before proposing a commit and read every verdict line;
  a gate that did not run is NOT RUN, never a pass.
- Keep plans and notes in `.work/` (gitignored); never commit them.
