---
description: >
  Supply-chain malware. npm postinstall installs a systemd user service that wipes data once the stolen token is revoked.
tags: [recall, supply-chain, threat]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  CRITICAL with Response order: tensorlake-wiper; remove the monitor before revoking tokens.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
