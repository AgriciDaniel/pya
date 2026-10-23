---
type: tool_used
# The orchestrator uses Bash only for its bundled scripts/*.py and read-only git diff, merge-base and rev-parse.
tool: Bash
input_match: '"command"\s*:\s*"(?!(?:[^"\\]|\\.)*scripts/[a-z_]+\.py)(?!git (?:-C \S+ )?(?:diff|merge-base|rev-parse)\b)'
min: 0
max: 0
weight: 0.5
arm: with-only
---
