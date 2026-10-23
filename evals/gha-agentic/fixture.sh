#!/usr/bin/env bash
# Scaffold for the gha-agentic eval case: two GitHub Actions workflows that run
# claude-code-action. claude-pr-review.yml has a real injection path; the
# scheduled docs-refresh.yml has dangerous settings but no untrusted input.
# The SHAs in docs-refresh.yml are random placeholders.
set -euo pipefail

# Write only into the eval run's empty workspace. Refuse anywhere else.
if [ "$PWD" = "/" ] || [ -n "$(ls -A .)" ]; then
  echo "refusing to scaffold: run this from an empty eval workspace" >&2
  exit 1
fi

mkdir -p .github/workflows docs

cat > .github/workflows/claude-pr-review.yml <<'EOF'
name: Claude PR review

on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: write
  pull-requests: write
  id-token: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --allowedTools "Bash(*)"
          prompt: |
            Review this pull request and push fixes for anything you find.
            Title: ${{ github.event.pull_request.title }}
            Description: ${{ github.event.pull_request.body }}
EOF

cat > .github/workflows/docs-refresh.yml <<'EOF'
name: Docs refresh

on:
  schedule:
    - cron: "17 3 * * 1"

permissions:
  contents: read

jobs:
  refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b3659129993fd0f13a589d2a2b04a8aed5034411 # v4
        with:
          persist-credentials: false

      - uses: anthropics/claude-code-action@0598ca2ccfeec129e226ffe2224b23f9d2f465c8 # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          allowed_non_write_users: "*"
          claude_args: --allowedTools "Bash(*)"
          prompt: |
            Regenerate docs/index.md from the headings in docs/*.md. Print the result only.
EOF

cat > docs/index.md <<'EOF'
# Docs

- [Getting started](getting-started.md)
EOF

cat > docs/getting-started.md <<'EOF'
# Getting started

Run `make dev`.
EOF

cat > README.md <<'EOF'
# widget-lib

A small library. Pull requests are reviewed by an AI action.
EOF
