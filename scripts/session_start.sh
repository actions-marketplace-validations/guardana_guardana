#!/usr/bin/env bash
# SessionStart hook: two lines of live state, so a session does not rediscover
# them with tool calls. Wired in .claude/settings.json.
cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/..}" 2>/dev/null || exit 0

work=$(ls .work/*.md 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\n' ' ')
dirty=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')

echo "Work in flight (.work/): ${work:-none}"
echo "Uncommitted paths in the tree: ${dirty} — some may not be yours; stage explicit paths only."
exit 0
