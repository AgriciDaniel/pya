---
type: regex
# The checkout of untrusted PR head code is named.
pattern: 'head\.sha|head\.ref|PR head|pull request head'
flags: i
match: contains
weight: 0.5
---
