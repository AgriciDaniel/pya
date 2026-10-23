---
description: >
  Diff scope. The branch's last commit adds one SQL injection; an untouched file has an older command injection.
tags: [precision, should-not-fire, diff]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  Reports only the new SQL injection in app/search.py; nothing about app/legacy_export.py.
---

This branch adds an order search endpoint. Run PYA in diff mode (`/pya --scope diff`) so it only reviews what this branch changed, and show me the complete report.
