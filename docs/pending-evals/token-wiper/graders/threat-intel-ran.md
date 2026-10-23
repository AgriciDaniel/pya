---
type: tool_used
# Indicator: the threat-intel agent was dispatched.
tool: Agent
input_match: '"subagent_type"\s*:\s*"pya:threat-intel"'
min: 1
weight: 0.5
arm: with-only
---
