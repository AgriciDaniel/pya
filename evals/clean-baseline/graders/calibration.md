---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture is a small Flask notes app written with safe patterns: parameterized sqlite3 queries,
subprocess called with a fixed argument list, SECRET_KEY read from the environment, werkzeug
password hashing, CSRF protection, autoescaped templates, and a unit test that uses the AWS
documentation example key AKIAIOSFODNN7EXAMPLE as a dummy value.

PASS if the report:
- has no CRITICAL or HIGH finding in its main findings;
- does not claim the parameterized queries, the list-argument subprocess call or the
  environment-loaded secret key are vulnerable;
- treats AKIAIOSFODNN7EXAMPLE as a documented example value (ignored or filtered, at most INFO),
  not as a leaked credential that must be rotated;
- words the result as no findings in the reviewed scope rather than proof that the app is secure.
Any LOW or INFO hardening notes are fine if they are labeled as such.

FAIL if it reports an invented vulnerability at HIGH or CRITICAL, tells the user to rotate the
example AWS key, or states the code is proven or guaranteed secure.
