---
description: >
  Trust store. Vendored cacert.pem with emSign roots and pip 26.2.1 in the Dockerfile; no secrets are exposed.
tags: [recall, should-not-fire, feed, tls]
runs: 3
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Skill, Read, Glob, Grep, Agent, TodoWrite]
expected_outcome: >
  TLS trust finding with Response order: emsign-trust; no secret rotation advice.
---

Run a full PYA security audit of this repository (`/pya`) and show me the complete report.
