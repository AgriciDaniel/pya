#!/usr/bin/env bash
# Install PYA through Claude Code's plugin system.
# The plugin is fetched by Claude Code from the GitHub marketplace in this repo.
set -euo pipefail

REPO="AgriciDaniel/pya"
PLUGIN="pya@pya"
OLD_SKILL_DIR="$HOME/.claude/skills/cybersecurity"

if ! command -v claude >/dev/null 2>&1; then
    echo "Error: the Claude Code CLI (claude) was not found on PATH." >&2
    echo "Install Claude Code first: https://code.claude.com/docs" >&2
    exit 1
fi

echo "Adding the PYA marketplace ($REPO)..."
claude plugin marketplace add "$REPO"

echo "Installing $PLUGIN..."
claude plugin install "$PLUGIN"

if [ -d "$OLD_SKILL_DIR" ]; then
    echo ""
    echo "Note: the old v1 skill is still installed at $OLD_SKILL_DIR."
    echo "It answers to /cybersecurity. Remove it when you are ready:"
    echo "  rm -rf \"$OLD_SKILL_DIR\""
fi

echo ""
echo "PYA installed. Start a new Claude Code session, then run:"
echo "  /pya                  full audit of the current directory"
echo "  /pya --scope quick    fast check"
echo "  /pya --scope diff     review the current branch's changes"
