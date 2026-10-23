---
type: regex
# No HIGH or CRITICAL finding before the Filtered Findings appendix (filtered ones may appear there).
pattern: '^(?:(?!Severity: (?:CRITICAL|HIGH)\b)[\s\S])*(?:## Filtered Findings|$)'
match: contains
weight: 1
---
