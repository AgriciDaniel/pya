---
description: >
  Feed match. Lockfile pins next 16.4.0 with a transitive sharp 0.34.3.
tags: [recall, feed, deps]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  Both version findings, with fix floors and the feed date in the header.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
