---
description: >
  WordPress backdoor. .user.ini prepend, a SQL trigger that restores the payload, and the fz_emer_done_v1 IOC option.
tags: [recall, threat, php]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  CRITICAL threat finding with Response order: wp-sc-backdoor and the prepend-first cleanup order.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
