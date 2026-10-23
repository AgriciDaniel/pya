---
type: regex
# Feed month, as-of date and age are always printed.
pattern: '\*\*Threat feed\*\*: \d{4}-\d{2} \(as of \d{4}-\d{2}-\d{2}, \d+ days? old\)'
match: contains
weight: 0.5
---
