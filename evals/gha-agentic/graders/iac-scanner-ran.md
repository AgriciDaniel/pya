---
type: tool_used
# Indicator: the IaC/CI scanner was dispatched.
tool: Agent
input_match: '"subagent_type"\s*:\s*"pya:iac-scanner"'
min: 1
weight: 0.5
arm: with-only
---
