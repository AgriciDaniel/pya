# Scoring Rubric

`scripts/score.py` implements this file. If you change a number here, change the script and its
tests in the same commit.

## Severity levels

Severity is the CVSS v4.0 base view: attack vector, complexity, privileges, user interaction and
impact.

| Severity | Typical examples |
|---|---|
| CRITICAL | Unauthenticated RCE, SQL injection with data access, auth bypass to full account takeover, container escape, confirmed malware or backdoor, malicious dependency version, a dependency in CISA KEV |
| HIGH | Stored XSS, privilege escalation, SSRF to internal services, insecure deserialization, JWT algorithm confusion, a live credential in the repo |
| MEDIUM | Reflected XSS, CSRF on non-critical actions, information disclosure, weak crypto, stale TLS trust store on a package client |
| LOW | Missing non-critical headers, verbose errors, minor misconfiguration |
| INFO | Defense-in-depth advice, not a concrete vulnerability |

## Exploitability inputs (for ordering, not for the score)

Use these to order the fix queue within a severity:

- **KEV** (CISA Known Exploited Vulnerabilities): exploited in the wild. Always "Act". Also caps the grade (see below).
- **EPSS**: the probability of exploitation in 30 days, when the dispatch provides it. Higher goes first.
- **SSVC** outcome words for the fix queue: **Act** (fix now), **Attend** (this sprint), **Track** (this month or backlog).

## Confidence

| Level | Meaning |
|---|---|
| HIGH | Pattern confirmed, attacker-controlled input reaches the sink, no compensating control visible |
| MEDIUM | Pattern confirmed, but a framework or middleware protection may exist outside the reviewed scope |
| LOW | Plausible pattern only; strong chance of mitigation |

Confidence goes up for:

- direct request input with no validation;
- no framework protection;
- sensitive data handled;
- internet-facing code;
- the same pattern in several places.

Confidence goes down for:

- known framework auto-protection;
- behind authentication;
- internal-only code;
- test code (except real credentials);
- read-only impact.

### Minified or generated code

Treat a file as minified or generated if two or more of these hold:

- it matches `*.min.js`, `*.bundle.js` or `*.chunk.js`;
- it is a single line over 1 KB;
- its header says it is generated;
- its identifiers are mangled.

Review the source or source map instead. Report from generated code only if no source exists, and then drop the confidence one level and add a caveat.

## Inline suppression comments

Suppression comments come from other tools: `# nosec`, `# nosemgrep`, `// NOLINT`, `// eslint-disable`, `# noqa`, `// nolint`, `# rubocop:disable`, `@SuppressWarnings`, `// noinspection`, `#pragma warning(disable)`, `trufflehog:ignore`.

Rules:

1. Never skip a finding because of one of these comments. It was written for another tool.
2. Note it in the finding as `Suppression: <marker> at line N`.
3. With no justification, raise confidence one step: someone knew the code was risky.
4. With a stated compensating control, keep normal confidence and name the control for a human to verify.

## Deductions per finding (category score)

Category score = 100 minus the sum of deductions, with a floor of 0. Only findings kept by the verifier count.

| Severity | HIGH confidence | MEDIUM confidence | LOW confidence |
|---|---|---|---|
| CRITICAL | 25 | 15 | 7 |
| HIGH | 15 | 10 | 5 |
| MEDIUM | 8 | 5 | 2 |
| LOW | 2 | 2 | 1 |
| INFO | 0 | 0 | 0 |

LOW-confidence deductions are half the MEDIUM value, rounded down.

## Overall score

| Agent | Weight |
|---|---|
| vuln-scanner | 18 |
| authz-reviewer | 14 |
| secret-scanner | 10 |
| dependency-auditor | 12 |
| iac-scanner | 9 |
| threat-intel | 13 |
| ai-code-auditor | 6 |
| logic-reviewer | 9 |
| agentic-auditor | 9 |

The weights total 100.

- **Not applicable** (`applicable: false`): the agent's weight is redistributed proportionally to the others.
- **Failed or invalid output:** the agent is **unreviewed**. It gets no score and its weight is removed. It is listed in the report and never treated as a neutral 50.
- **Overall** = sum of (category score times weight) over completed applicable agents, divided by the sum of their weights.

## Grades and caps

| Grade | Score | Action |
|---|---|---|
| A | 90 to 100 | Maintain; minor hardening |
| B | 75 to 89 | Fix in the regular sprint |
| C | 50 to 74 | Security sprint; fix all HIGH and above |
| D | 25 to 49 | Fix CRITICAL now |
| F | 0 to 24 | Stop deploys; incident response mode |

The grade is capped at **C** when any of these hold. Print every reason as `Grade capped at C: <reason>`.

1. A kept CRITICAL finding with HIGH confidence.
2. Any dependency, image or runtime match flagged `kev: true`.
3. Coverage below 75 percent of files in scope.
4. Dispatched agents failed, and either fewer than 6 completed or more than a quarter of those dispatched failed.
   Agents not dispatched on purpose (scope, `--focus`, area absent) are passed as `skipped` and never count as failures.

A capped grade never rises above C. A lower computed grade stays lower.

A result with no findings is worded "No findings in reviewed scope. This is not proof of absence."

## Finding IDs

The orchestrator renumbers after aggregation, deduplication and verification: `VULN-001`, `VULN-002` and so on in severity order. Chains keep the `CHAIN:` title prefix and get a `VULN-` number like any other finding.
