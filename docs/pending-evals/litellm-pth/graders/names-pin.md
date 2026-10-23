---
type: regex
# The malicious litellm 1.107.0 pin is reported.
pattern: 'litellm[^\n]{0,40}1\.107\.0'
match: contains
weight: 1
---
