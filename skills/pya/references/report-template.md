# Report Template

The orchestrator renders this template. The eval suite greps for exact strings, so keep the
labels in **bold** and the `##` headings exactly as written.

## Header and summary

```markdown
# PYA Security Audit Report

**Project**: <name> | **Date**: <YYYY-MM-DD> | **Scope**: <full|quick|diff|focus:<agent>>
**Overall**: <NN>/100 (Grade <X>)
<one line per cap, only when capped>Grade capped at C: <reason>
**Findings**: Critical <n> | High <n> | Medium <n> | Low <n> | Info <n> (after verification; <m> filtered)
**Threat feed**: <YYYY-MM> (as of <YYYY-MM-DD>, <N> days old)<if stale: , STALE: refresh the feed>
**Agents completed**: <x>/<applicable> (<names of unreviewed agents, if any>)
**Tech stack**: <languages, frameworks>
```

A CRITICAL finding with HIGH confidence also gets this banner directly under the header:
`> CRITICAL issues found. Do not deploy until the "Act now" items are fixed.`

A run with no findings prints:
`No findings in reviewed scope. This is not proof of absence.`

## Scope and Coverage (always present)

```markdown
## Scope and Coverage

Files in scope: <n> | Files reviewed: <n> (<pct>%) | Not reviewed: <dirs or categories>

| Tool | Status | Notes |
|---|---|---|
| osv-scanner | ran / not_installed / not_run / failed | <offline DB date or reason> |
| trufflehog | ... | verification <off|on> |
| zizmor | ... | |
| semgrep | ... | |
| feed_match | ran | <n> matches |
| ioc_scan | ran | <n> hits |

Online checks: <off | on (--online)>
```

## Category scores

```markdown
## Category Scores

| Agent | Score | Weight | Status | Top finding |
|---|---|---|---|---|
| vuln-scanner | 82 | 18 | completed | VULN-004 ... |
| agentic-auditor | n/a | 0 | not applicable | |
| iac-scanner | n/a | removed | unreviewed (agent failed) | |
```

## Finding format

```markdown
[VULN-001] <Specific title>
Severity: <CRITICAL|HIGH|MEDIUM|LOW|INFO> | Confidence: <HIGH|MEDIUM|LOW> | Verified: <n>/10
CWE: <CWE-89> | OWASP: <A05:2025> | ATT&CK: <T1546.018> | AI: <ASI02, LLM05>
Location: <file:line> (flow: <file:line> to <file:line>)
Feed: <PYA-2026-10-012, KEV> (only for feed matches)
Response order: <key> (only when a key applies; then list the steps from response-order.md)

WHAT: <one or two sentences>
EXPLOIT: <concrete attacker, input, outcome>
EVIDENCE:
    <at most 6 lines, secrets masked>
FIX: <specific change; before and after when short>
Sources: <URLs, for feed-derived findings>
```

Omit the `ATT&CK`, `AI`, `Feed` and `Response order` parts when they do not apply.

Example:

```markdown
[VULN-001] Python startup hook executes on every interpreter start
Severity: CRITICAL | Confidence: HIGH | Verified: 10/10
CWE: CWE-506 | OWASP: A03:2025 | ATT&CK: T1546.018
Location: vendor/site-packages/cook.pth:1
Feed: PYA-2026-10-001
Response order: litellm-pth

WHAT: A .pth file runs an import line at every Python start, decoding and executing a payload.
EXPLOIT: Any python or pip run in this environment executes the payload, which reads cloud and
CI credentials and posts them to a hardcoded host.
EVIDENCE:
    import base64,os;exec(base64.b64decode("aW1w****ZCgp"))
FIX: Follow the response order below. Do not run pip first.
Sources: https://docs.litellm.ai/blog/security-incident-oct-21-2026
```

## Remaining sections, in this order

```markdown
## Top Findings
<the five highest, one line each>

## Detailed Findings
### Critical
### High
### Medium
### Low
### Informational   (one line each)

## Threat Intelligence
| Finding | ATT&CK | Indicator | Feed entry |

## Attack Paths
<CHAIN: findings, with the single fix that breaks each chain>

## Compliance Status
<only with --compliance; requirement, status, findings>

## Fix Queue
### Act now
### This sprint (Attend)
### This month (Track)
### Backlog

## Filtered Findings
<candidates the verifier dropped: id, title, failed gate, one-line justification>

## Methodology
- Standards: see references/standards.md (OWASP Top 10:2025, CWE Top 25 2025, ATT&CK v20, OWASP LLM 2025, Agentic 2026, MCP Top 10, ASVS 5.0.0, CVSS 4.0)
- Specialist agents with enforced read-only tools, one verifier pass per serious finding
- Deterministic measurement: feed_match, ioc_scan, and optional osv-scanner, trufflehog, zizmor, semgrep
- Static review only: this does not replace dynamic testing, penetration testing or runtime monitoring
- Limits: an area with no findings is not proof of absence. Unreviewed files and tools that did not run are listed under Scope and Coverage
```
