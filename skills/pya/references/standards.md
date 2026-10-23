# Standards and Versions (single source of truth)

Every other reference file uses the versions in this table. When a standard changes, edit this
file first, then follow "How to refresh" below. Last full check: **2026-10-23**.

## Mapping targets used in findings

| Standard | Version PYA uses | Version date / status | Primary URL | Used in |
|---|---|---|---|---|
| OWASP Top 10 | 2025 (A01 to A10) | 2025 edition | https://top10.owasp.org/2025 | `owasp` field on every finding |
| CWE Top 25 | 2025 list | CISA alert 2025-12-11 | https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html and https://www.cisa.gov/news-events/alerts/2025/12/11/2025-cwe-top-25-most-dangerous-software-weaknesses | `cwe` field, vulnerability-taxonomy.md |
| MITRE ATT&CK (Enterprise) | v20 | 2026-10-13 | https://attack.mitre.org/resources/versions/ and https://attack.mitre.org/resources/updates/ | `attack` field, threat-intelligence.md |
| ATT&CK T1546.018 Python Startup Hooks | added in v18 | v18 | https://attack.mitre.org/techniques/T1546/018/ | `.pth` / `sitecustomize` findings |
| OWASP Top 10 for LLM Applications | 2025 (LLM01 to LLM10) | 2025 edition | https://genai.owasp.org/llm-top-10/ | `ai_ids` |
| OWASP Top 10 for Agentic Applications | 2026 (ASI01 to ASI10) | published 2025-12-09 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | `ai_ids` (names from secondary sources; confirm against the official PDF) |
| OWASP MCP Top 10 | 2025 IDs (MCP01:2025 to MCP10:2025), beta | Phase 3 beta | https://owasp.org/www-project-mcp-top-10/ | `ai_ids` |
| OWASP AI Testing Guide | current | living document | https://owasp.org/www-project-ai-testing-guide/ | agentic-security.md test ideas |
| OWASP ASVS | 5.0.0 (cite as `v5.0.0-x.y.z`) | 5.0.0 | https://github.com/OWASP/ASVS/tree/master/5.0/en | remediation guidance, compliance-matrix.md |
| OWASP API Security Top 10 | 2023 | 2023 edition | https://api-security.owasp.org/ | API findings |
| MCP specification | 2026-07-28 | 2026-07-28 | https://modelcontextprotocol.io/specification/2026-07-28 | MCP server code checks |
| MCP security best practices | 2026-07-28 | 2026-07-28 | https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices | MCP server code checks |

## Scoring and exploitability inputs

| Standard | Version | Date / status | Primary URL | Used in |
|---|---|---|---|---|
| CVSS | 4.0 | current | https://www.first.org/cvss/ | severity |
| EPSS | current model | daily scores | https://www.first.org/epss/ | exploitability input |
| SSVC | outcome words Act, Attend, Track | current | https://www.cisa.gov/ssvc | remediation queue wording |
| CISA KEV | catalog (record `catalogVersion`) | live | https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | KEV gate (auto CRITICAL, grade cap C) |

## Compliance targets (`--compliance`)

| Target | Version | Date / status | Primary URL | Notes |
|---|---|---|---|---|
| `pci` PCI DSS | 4.0.1 | 6.4.3 and 11.6.1 in force since 2025-03-31 | https://www.pcisecuritystandards.org/rfc_instructions_pci-dss-v4-0-1-june2026/ | payment-page script controls |
| `hipaa` HIPAA Security Rule | current 45 CFR 164.312 | NPRM pending, final rule now targeted for July 2027 | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C and (secondary) https://www.alston.com/en/insights/publications/2026/07/hhs-delays-hipaa-security-rule-2027 | map to current text only |
| `nist` NIST SP 800-53 | Release 5.2.0 | 2025-08-27 | https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls | adds SA-15(13), SA-24, SI-02(07) |
| `ssdf` NIST SP 800-218 SSDF | v1.1 (final) | 1.2 is an initial public draft, not final | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd | cite v1.1 practice IDs only |
| `csf` NIST CSF | 2.0 | current | https://www.nist.gov/cyberframework | functions GV, ID, PR, DE, RS, RC |
| `soc2` SOC 2 TSC | 2017 TSC with revised points of focus (2022) | criteria unchanged since 2017 | https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 | points of focus are guidance, not requirements |
| `gdpr` GDPR | Regulation (EU) 2016/679 | in force | https://eur-lex.europa.eu/eli/reg/2016/679/oj | Art. 25, 32 |
| `cra` EU Cyber Resilience Act | Art. 14 reporting | applies since 2026-09-11 | https://ncsc.gov.ie/cra/ | 24h / 72h / 14 days or one month |
| EU AI Act (context only) | Omnibus date shift | Annex III obligations now apply 2027-12-02 | (secondary) https://www.addleshawgoddard.com/en/insights/insights-briefings/2026/technology/eu-ai-act-ai-omnibus-formally-adopted/ | cite as context, never as a finding |

## Supply-chain and platform references

| Item | Version / state | Date | Primary URL |
|---|---|---|---|
| SLSA | v1.2 (adds Source Track) | current | https://slsa.dev/spec/v1.2/whats-new |
| OpenSSF Scorecard | current release | see releases | https://github.com/ossf/scorecard/releases |
| npm v12 | dependency install scripts off by default; opt back in via `allowScripts` (package.json), `allow-scripts` (.npmrc), `npm approve-scripts` | GA 2026-07-08 | https://github.blog/changelog/2026-06-24-upcoming-breaking-changes-for-npm-v12/ and https://github.com/npm/cli/releases/tag/v12.0.0 |
| npm token changes | granular tokens, trusted publishing | 2025-09-29 | https://github.blog/changelog/2025-09-29-strengthening-npm-security-important-changes-to-authentication-and-token-management/ |
| PyPI attestations | current | current | https://docs.pypi.org/attestations/ |
| GitHub Actions SHA-pinning policy | org/repo policy can block unpinned actions | 2025-08-15 | https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/ |
| `pull_request_target` change | always runs the default-branch workflow | effective 2025-12-08 (announced 2025-11-07) | https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/ |
| GitHub immutable releases | GA, with release attestations | 2025-10-28 | https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases |
| Verifying a release | `gh release verify`, `gh release verify-asset` | current | https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/verifying-the-integrity-of-a-release |
| actions/checkout | v7, `persist-credentials` still defaults to `true` | current | https://github.com/actions/checkout |
| zizmor | v1.31.1, repo `zizmorcore/zizmor` | current | https://github.com/zizmorcore/zizmor and https://docs.zizmor.sh/audits/ |

## Claude Code and agent-platform docs (agentic-auditor)

| Item | URL |
|---|---|
| Claude Code hooks | https://code.claude.com/docs/en/hooks.md |
| Claude Code settings | https://code.claude.com/docs/en/settings-reference.md |
| Plugin security | https://code.claude.com/docs/en/plugins/security.md |
| Plugin marketplace reference | https://code.claude.com/docs/en/plugins/marketplace-reference.md |
| Agent Skills security | https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#security-considerations |
| Agent Skills spec | https://agentskills.io/specification |
| Claude Code security advisories | https://github.com/anthropics/claude-code/security/advisories |

## How to refresh

Do this monthly, alongside the new `feed/YYYY-MM.json`, and whenever a standard announces a release.

1. Re-open every URL in the tables above. Update the version, date and status columns here first.
2. Record anything you could not open as "not re-verified on YYYY-MM-DD" in the row, never as confirmed.
3. Find stale strings in the other references and fix them:
   - `grep -rn "2021\|A0[0-9]:2021\|Top 25:2024\|v1[5-9]\b\|ASVS 4" skills/pya/references`
   - `grep -rn "woodruffw/zizmor\|PCI DSS 4.0 \|SSDF 1.2" skills/pya/references`
4. If OWASP Top 10 or the CWE Top 25 changes, rebuild the cross-reference table in
   `vulnerability-taxonomy.md` and the cross-framework table in `compliance-matrix.md` together.
5. If ATT&CK changes, update the version line at the top of `threat-intelligence.md` and every
   technique ID that was renamed, deprecated or moved (check the "updates" page).
6. Version floors, CVE IDs and IOCs never go in these references. They go in the dated feed.
7. Run the dash check (U+2014, U+2013 count must be 0) and the seed-coverage test before committing.
