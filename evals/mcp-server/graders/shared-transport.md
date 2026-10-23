---
type: regex
# The transport shared across clients is reported.
pattern: '(?:shared|single|global|one)[^\n]{0,40}transport|transport[^\n]{0,40}(?:shared|reused|across)'
flags: i
match: contains
weight: 1
---
