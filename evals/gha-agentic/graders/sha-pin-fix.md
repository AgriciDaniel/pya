---
type: regex
# Fix pins actions to full commit SHAs.
pattern: 'pin[^\n]{0,60}\bSHA|SHA[- ]pin|full[- ]length[^\n]{0,20}SHA|commit SHA'
flags: i
match: contains
weight: 1
---
