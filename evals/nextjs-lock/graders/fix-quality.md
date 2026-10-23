---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture is a Next.js app whose package-lock.json resolves next 16.4.0 and, through next, sharp
0.34.3. The threat feed lists next below 16.4.1 and sharp below 0.35.5 as affected.

PASS if the report has a finding for each package, cites the lockfile as evidence, attributes the
version floors to the dated threat feed, and gives a concrete fix: upgrade next to 16.4.1 or later
and make sure the lockfile resolves sharp 0.35.5 or later (a lockfile refresh or an override), then
rebuild.

FAIL if either package is missed, if the fix is only "update your dependencies" with no versions,
or if the report claims it checked a live advisory database or ran npm audit.
