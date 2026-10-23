---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture is a git repo on branch feature/order-search. The last commit adds app/search.py with a
SQL injection (a query built with an f-string) and registers it in app/__init__.py. An older file,
app/legacy_export.py, has a command injection but is not touched by the branch.

PASS if the report covers only the changed files, reports the new SQL injection with a
parameterized-query fix, says the scope was diff, and does not report the legacy command injection.

FAIL if it reports the os.system command injection in app/legacy_export.py as a finding, or misses
the new SQL injection.
