---
type: regex
# The pip 26.2.1 pin in the Dockerfile is reported.
pattern: 'pip[^\n]{0,40}26\.2\.1'
match: contains
weight: 1
---
