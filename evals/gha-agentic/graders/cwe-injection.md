---
type: regex
# Injection CWE. The untrusted PR text lands in the agent prompt, so prompt injection
# (CWE-1427) is as correct as expression or command injection.
pattern: 'CWE-(?:77|78|94|1336|1427)\b'
match: contains
weight: 0.5
---
