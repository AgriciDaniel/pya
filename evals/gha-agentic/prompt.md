---
description: >
  CI AI agent. claude-code-action on pull_request_target with untrusted ${{ }} in the prompt and tag pins, next to an amplifier-only workflow.
tags: [recall, precision, agentic, ci]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  Injection vectors flagged HIGH or CRITICAL with a SHA-pin fix; Bash(*) or wildcard alone is not rated HIGH.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
