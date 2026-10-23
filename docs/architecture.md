# PYA architecture (v2)

This file is the contract between the orchestrator skill, the specialist agents, the
deterministic scripts, the threat feed and the eval suite. Change it first, then the parts.

## Layout

```text
.claude-plugin/plugin.json        plugin "pya"
.claude-plugin/marketplace.json   single-plugin marketplace (source "./")
skills/pya/SKILL.md               orchestrator (/pya), under 500 lines
skills/pya/references/            knowledge loaded on demand by agents
skills/pya/references/seeds.json  permanent technique seeds (regex), tested
skills/pya/feed/schema.json       JSON Schema for monthly feed files
skills/pya/feed/YYYY-MM.json      dated threat feed (versions, IOCs, sources)
skills/pya/scripts/               stdlib-only Python, run with python3 -I
agents/*.md                       specialist agents with enforced tool allowlists
evals/<case>/                     claude plugin eval cases
tests/                            pytest for scripts, feed and seeds
docs/                             architecture and maintenance docs
```

## Run order

1. **Gather** (orchestrator): stack, entry points, trust boundaries, STRIDE.
2. **Measure** (orchestrator, Bash, scripts only):
   - `scripts/inventory.py <target>` lists manifests, lockfiles, IaC, CI files and agent config files.
   - `scripts/feed_match.py <target>` matches pinned versions against the newest feed.
   - `scripts/ioc_scan.py <target>` matches technique seeds and feed IOCs.
   - `scripts/run_tools.py <target>` runs osv-scanner, trufflehog, zizmor and semgrep if they are installed. All of them run offline by default.
3. **Discover**: the specialist agents run in parallel. Each gets the context payload, the measured results for its area, and the reference paths.
4. **Verify**: one `pya:finding-verifier` pass runs per CRITICAL or HIGH candidate.
5. **Score**: `scripts/score.py --data '<single-line JSON>'` computes the category, overall, grade and caps.
6. **Report**: the orchestrator renders `references/report-template.md`.

## Agents

| Agent file | Spawn name | Weight | Owns |
|---|---|---|---|
| agents/vuln-scanner.md | pya:vuln-scanner | 18 | injection, XSS, SSRF, path traversal, deserialization, crypto, memory safety |
| agents/authz-reviewer.md | pya:authz-reviewer | 14 | authn, authz, IDOR, sessions, JWT, OAuth |
| agents/secret-scanner.md | pya:secret-scanner | 10 | secrets, exposure paths, token leakage into logs |
| agents/dependency-auditor.md | pya:dependency-auditor | 12 | lockfiles, feed matches, malicious packages, install scripts |
| agents/iac-scanner.md | pya:iac-scanner | 9 | Docker, compose, K8s, Terraform, CI/CD, php.ini, ssh config |
| agents/threat-intel.md | pya:threat-intel | 13 | backdoors, persistence, C2, exfiltration, wipers, IOCs |
| agents/ai-code-auditor.md | pya:ai-code-auditor | 6 | AI-generated code smells, hallucinated imports, insecure defaults |
| agents/logic-reviewer.md | pya:logic-reviewer | 9 | business logic, races, attack chains, missing controls |
| agents/agentic-auditor.md | pya:agentic-auditor | 9 | agent configs, MCP, skills, hooks, LLM integration, AI CI actions |
| agents/finding-verifier.md | pya:finding-verifier | n/a | keep or drop one candidate finding |

Every scanner agent has `tools: Read, Grep, Glob`. None has Bash, Write, Edit or any network
tool. Weights are integers summing to 100. When an agent's area is absent (no IaC, no agent or
LLM surface), it reports `applicable: false` and its weight is redistributed proportionally.

## Agent output contract

Each scanner agent ends its reply with exactly one fenced `json` block:

```json
{
  "agent": "vuln-scanner",
  "applicable": true,
  "coverage": {"files_in_scope": 120, "files_reviewed": 96, "not_reviewed": ["vendor/", "dist/"]},
  "findings": [
    {
      "id": "VULN-TMP-1",
      "title": "SQL injection in user lookup",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "file": "app/routes/users.py",
      "line": 34,
      "flow": ["app/routes/users.py:31", "app/routes/users.py:34"],
      "cwe": "CWE-89",
      "owasp": "A05:2025",
      "attack": null,
      "ai_ids": [],
      "what": "One or two sentences.",
      "exploit_scenario": "How an attacker uses it, concretely.",
      "fix": "Specific fix.",
      "evidence": "Short redacted snippet.",
      "response_order": null,
      "feed_id": null,
      "kev": false,
      "sources": []
    }
  ]
}
```

Field rules:

- `severity`: one of CRITICAL, HIGH, MEDIUM, LOW, INFO.
- `confidence`: one of HIGH, MEDIUM, LOW.
- `owasp`: an ID from OWASP Top 10:2025 (A01 to A10), or null.
- `attack`: an ATT&CK v20 technique ID such as T1546.018, or null.
- `ai_ids`: IDs from OWASP LLM Top 10 2025 (LLM01 to LLM10), Agentic Top 10 2026 (ASI01 to ASI10) or MCP Top 10 (MCP01 to MCP10).
- `response_order`: a key from `references/response-order.md`, or null.
- `feed_id`: the feed entry ID when the finding came from a feed match.
- `evidence`: secrets are masked as the first 4 and last 4 characters only; private keys show only their header line.

The verifier returns one fenced `json` block:
`{"id": "...", "keep": true, "confidence": 1-10, "gates": {"process": "pass|fail|n/a", "reachability": "...", "impact": "...", "poc": "...", "bounds": "...", "environment": "..."}, "justification": "..."}`.

Findings with `keep: false` or `confidence < 8` are dropped from the main report and listed in
the "Filtered" appendix with the justification.

## Feed contract

See `skills/pya/feed/schema.json`. Each entry has:

- **Identity:** an `id`, an `ecosystem` and a `package` (or a `kind` for non-package items).
- **Affected versions:** OSV-style `ranges` (`introduced`/`fixed`) and/or exact `versions`.
- **Classification:** `severity`, `kev`, `malicious` and `confidence`.
- **Indicators:** `iocs`.
- **Remediation:** `response_order` and `fixed_in`.
- **Provenance:** `sources` (at least one URL), plus `as_of` and `expires`.

The report header always prints the feed month, its `as_of` date and its age in days. Feeds more than 35 days old raise a warning.

## Scoring contract (scripts/score.py)

- Category score is 100 minus the sum of deductions. Deductions are in `references/scoring-rubric.md`, and the score floors at 0.
- Overall score is the weighted mean over applicable, completed agents.
- An agent that failed is "unreviewed". It gets no score, and its weight is removed.
- Grade bands: A 90 or more, B 75 or more, C 50 or more, D 25 or more, F below 25.
- These conditions cap the grade at C:
  - any kept CRITICAL with HIGH confidence;
  - any KEV match;
  - coverage below 75 percent of files in scope;
  - dispatched agents failed and either fewer than 6 completed or more than a quarter failed.
- Agents not dispatched on purpose (scope, `--focus`, or an absent area) are passed in `skipped`.
  They are neither scored nor counted as failures.
- A clean result is always worded "no findings in reviewed scope, not proof of absence".
