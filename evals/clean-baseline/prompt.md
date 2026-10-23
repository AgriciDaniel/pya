---
description: >
  Precision case. A small Flask app written with safe patterns; PYA must not invent serious findings.
tags: [precision, should-not-fire]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  Grade A or B, no CRITICAL or HIGH in the main findings, clean result worded as not proof of absence.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
