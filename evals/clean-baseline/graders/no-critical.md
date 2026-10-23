---
type: regex
# Precision check: nothing in this fixture is CRITICAL.
pattern: 'Severity: CRITICAL\b'
match: not_contains
weight: 1.5
---
