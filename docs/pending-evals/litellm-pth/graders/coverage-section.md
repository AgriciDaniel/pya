---
type: regex
# Coverage section with all four tools and a status word after it.
pattern: '## Scope and Coverage(?=[\s\S]*osv-scanner)(?=[\s\S]*trufflehog)(?=[\s\S]*zizmor)(?=[\s\S]*semgrep)(?=[\s\S]*\b(?:ran|not_installed|not_run|failed)\b)'
match: contains
weight: 0.5
---
