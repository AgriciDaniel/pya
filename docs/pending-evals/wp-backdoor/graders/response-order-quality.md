---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture is a WordPress site repo with a .user.ini that sets auto_prepend_file to a disguised
loader, a SQL migration that creates a trigger restoring a payload option (fz_emer_done_v1), and the
loader file itself.

PASS if the report treats this as a CRITICAL backdoor and orders the cleanup as: neutralize the
auto_prepend_file line first; then remove the off-disk copies (the database trigger, the payload
option, any cron entries); delete the PHP files last. Recommending a check for further persistence
and a restore from a pre-compromise backup is fine.

FAIL if it says to delete the PHP files first, treats the trigger as an ordinary migration, or
treats the whole thing as a configuration issue rather than a backdoor.
