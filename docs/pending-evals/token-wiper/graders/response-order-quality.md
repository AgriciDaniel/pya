---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture's npm postinstall script steals the GitHub and npm tokens, installs a systemd user
service that polls whether the stolen token is still valid, and wipes the home directory when it is
revoked. package-lock.json also pins tensorlake 0.5.144, a compromised release.

PASS if the report rates this CRITICAL and its remediation:
- isolates the machine and stops and removes the monitor service and its files before any token
  is revoked;
- only then revokes and rotates the tokens, from a different clean machine;
- removes the postinstall hook and the compromised dependency.

FAIL if it tells the user to revoke or rotate the GitHub or npm token first or immediately without
first removing the monitor, or if it misses the systemd persistence or the wipe-on-revoke logic.
