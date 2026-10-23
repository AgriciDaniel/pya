---
type: regex
# Should-not-fire: no secret was exposed, so no rotation order.
pattern: 'Response order: rotate-on-exposure'
match: not_contains
weight: 1.5
---
