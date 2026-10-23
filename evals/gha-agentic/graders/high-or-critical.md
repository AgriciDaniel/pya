---
type: regex
# The injection path is rated HIGH or CRITICAL.
pattern: 'Severity: (?:CRITICAL|HIGH)\b'
match: contains
weight: 1
---
