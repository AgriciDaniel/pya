# Changelog

All notable changes to PYA (formerly claude-cybersecurity) are documented here.

## [2.0.0] - 2026-10-23

Renamed to **PYA (Protect Your Ass)**. The command is now `/pya`, and the plugin name is `pya`.

### Migration from v1
- Install as a plugin: `/plugin install pya --marketplace AgriciDaniel/claude-cybersecurity`.
- The old skill at `~/.claude/skills/cybersecurity` keeps answering to `/cybersecurity` until you remove it with `rm -rf ~/.claude/skills/cybersecurity`.
- Flags are unchanged: `--scope`, `--focus` and `--compliance`. New: `--online`, `--focus agentic`, `--compliance cra`.

### Added
- **Agentic auditor (agent 9).** Covers agent configs, MCP servers and clients, skills, hooks, AI agents in GitHub Actions, and LLM application code. Maps findings to OWASP LLM Top 10 2025, Agentic Top 10 2026, MCP Top 10 and ATT&CK v20.
- **Verifier.** One pass per CRITICAL or HIGH finding, using six gates. Dropped findings appear under "Filtered Findings".
- **Enforced tool limits.** Every specialist is a plugin agent in `agents/` with `tools: Read, Grep, Glob`.
- **Deterministic scripts** in `skills/pya/scripts/`: inventory, feed_match, ioc_scan, run_tools, score, update_kev and validate_feed.
- **Dated threat feed.** `skills/pya/feed/2026-10.json` is built from the verified October 2026 digest, and every entry cites its source.
- **Optional offline scanners.** osv-scanner, trufflehog, zizmor and semgrep run when installed.
- **Response-order playbook.** Findings say when the order of the fix matters, for example removing a wiper before revoking tokens.
- **New detections:**
  - Python startup-hook persistence (`.pth`, `sitecustomize.py`);
  - token-revocation wipers;
  - `.user.ini` prepend backdoors;
  - vendored CA bundles that still trust emSign;
  - Next.js `use cache` and SVG image issues;
  - `Math.random` tokens;
  - npm v12 install-script settings;
  - `persist-credentials` and `pull_request_target` head checkouts.
- **Evals** for `claude plugin eval`, plus a pytest suite and `make check`.
- **Manifests and icon:** marketplace manifest, plugin icon, SHA-pinned CI with zizmor, and an eval workflow on release tags.

### Changed
- **Standards.**

  | Standard | From | To |
  |---|---|---|
  | OWASP Top 10 | 2021 | 2025 |
  | CWE Top 25 | 2024 | 2025 |
  | MITRE ATT&CK | v15 | v20 |

  Also added: ASVS 5.0.0, PCI DSS 4.0.1, NIST SP 800-53 Release 5.2.0, and EU CRA reporting duties.
- **Scoring moved into `score.py`.**
  - A failed agent is "unreviewed", not a neutral 50.
  - Agents that do not apply have their weight redistributed.
  - The grade is capped at C for a confirmed critical, a KEV match, coverage below 75%, or too many failed agents. Agents skipped on purpose (quick scope, `--focus`) do not count as failures.
- **SKILL.md.** Cut from 986 to under 300 lines. Agent prompts moved to `agents/`.
- **Install path.** `install.sh` now installs through Claude Code's plugin system. The self-referential checksum file is removed.

### Fixed
- **`user-invokable`** was misspelled. Claude Code ignored it; the field is now `user-invocable`.
- **OWASP IDs.** The taxonomy used several wrong 2025 IDs, and SKILL.md still cited 2021.
- **GitHub Actions example.** The "safe" example interpolated a secret directly into `run:`.
- **Incident dates.** The Shai-Hulud and Nx facts in the references were dated and attributed incorrectly.
- **CI pins.** CI pinned actions by tag; they are now pinned to full SHAs, with `persist-credentials: false`.
- **Unverifiable statistics** were removed from the reference files.

## [1.0.1] - 2026-04-15
### Security
- Remove WebFetch/WebSearch phantom permissions (VULN-003, VULN-006)
- Add prompt injection defense to agent dispatch (VULN-001)
- Add .claude/ to file exclusion list (VULN-004)
- Add integrity verification to install script (VULN-002)
- Fix permission path mismatch in settings.local.json (VULN-014)
- Add per-agent tool restrictions (VULN-010)
- Add evidence redaction rules for secret masking (VULN-007)
- Add agent failure handling with Step 2.5 validation (VULN-013)

### Fixed
- Correct OWASP Top 10 references from 2025 to 2021
- Remove unsubstantiated statistical claims
- Remove references to nonexistent install.ps1
- Harden .gitignore with certificate/key patterns

### Added
- CI/CD pipeline with shellcheck, markdown linting, and checksum verification
- checksums.sha256 for file integrity verification
- CHANGELOG.md for release tracking

## [1.0.0] - 2026-04-11
### Added
- Initial release
- 8 parallel specialist agents with weighted scoring
- 25 CWE categories, 11 language pattern files, 4 IaC pattern files
- STRIDE threat modeling, MITRE ATT&CK v15 mapping
- Framework-aware false-positive suppression (10 frameworks)
- Compliance matrix (PCI DSS 4.0, HIPAA, SOC 2, GDPR, NIST 800-53)
