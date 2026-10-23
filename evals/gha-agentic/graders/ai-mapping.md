---
type: regex
# AI agent finding carries an OWASP AI ID.
pattern: 'ASI\d{2}|LLM\d{2}'
match: contains
weight: 0.5
---
