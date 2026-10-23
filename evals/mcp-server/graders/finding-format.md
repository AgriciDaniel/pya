---
type: regex
# At least one finding in the [VULN-NNN] / Severity | Confidence format.
pattern: '\[VULN-\d{3}\][^\n]*\n(?:[^\n]*\n){0,2}Severity: (?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\b[^\n]*\| Confidence: (?:HIGH|MEDIUM|LOW)'
match: contains
weight: 0.5
---
