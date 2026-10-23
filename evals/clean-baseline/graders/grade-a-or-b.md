---
type: regex
# A safe app should grade A or B.
pattern: '\*\*Overall\*\*: \d{1,3}(?:\.\d+)?/100 \(Grade [AB]\)'
match: contains
weight: 1.5
---
