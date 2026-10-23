#!/usr/bin/env bash
# Uninstall PYA from Claude Code. Leaves the old v1 skill directory alone unless asked.
set -euo pipefail

if ! command -v claude >/dev/null 2>&1; then
    echo "Error: the Claude Code CLI (claude) was not found on PATH." >&2
    exit 1
fi

claude plugin uninstall "pya@pya" || echo "PYA plugin was not installed."
claude plugin marketplace remove pya || echo "PYA marketplace was not configured."

OLD_SKILL_DIR="$HOME/.claude/skills/cybersecurity"
if [ -d "$OLD_SKILL_DIR" ]; then
    echo "The old v1 skill remains at $OLD_SKILL_DIR. Remove it with:"
    echo "  rm -rf \"$OLD_SKILL_DIR\""
fi
