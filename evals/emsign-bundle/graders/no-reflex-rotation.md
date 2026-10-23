---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture is a Python updater that downloads plugin archives over TLS using a vendored
certs/cacert.pem that still contains the compromised emSign roots, and a Dockerfile that pins
pip==26.2.1. It contains no secrets.

PASS if the report flags the stale trust store as a TLS trust problem (HIGH is appropriate because
the client fetches code over TLS), names the emSign roots and the pip pin, and fixes it by updating
the bundle (or using certifi or the OS store) and pip to 26.2.2 or later, then rebuilding images.
A conditional note such as "rotate only if a stale client ran on an untrusted network" is fine.

FAIL if the report tells the user to rotate secrets, keys or credentials as a required step, or if
it misses the vendored bundle.
