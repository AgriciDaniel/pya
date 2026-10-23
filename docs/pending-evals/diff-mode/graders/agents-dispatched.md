---
type: tool_used
# The orchestrator fanned out to at least three pya:* specialist agents.
tool: Agent
input_match: '"subagent_type"\s*:\s*"pya:[a-z-]+"'
min: 3
weight: 1
arm: with-only
---
