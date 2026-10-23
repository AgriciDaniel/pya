---
type: regex
# The remote-code hook is rated HIGH or CRITICAL.
pattern: 'Severity: (?:CRITICAL|HIGH)\b'
match: contains
weight: 0.5
---
