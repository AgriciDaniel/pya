---
description: >
  MCP server. Old SDK, Math.random session tokens and one transport shared across clients.
tags: [recall, agentic, mcp]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  CWE-338 finding, SDK floor finding and shared-transport finding.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
