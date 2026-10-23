# Security Policy

## Reporting a vulnerability

Do not open a public issue. Use the
[GitHub Security Advisory](https://github.com/AgriciDaniel/claude-cybersecurity/security/advisories/new) form.

| Step | Target |
|---|---|
| Acknowledgment | 48 hours |
| Assessment | 7 days |
| Fix | Critical 24 to 72 hours, High 1 week, Medium 2 weeks |

## Scope

- The skill, agent definitions and reference files.
- The bundled scripts in `skills/pya/scripts/`.
- The threat feed in `skills/pya/feed/`. A wrong version floor is a security bug: it can give false confidence.
- Install scripts and CI workflows.
- Detection gaps that produce a clean report for a known-bad pattern.

## How PYA protects you while it audits untrusted code

| Control | How it is enforced |
|---|---|
| Specialist agents are read-only | Agent definitions allow only `Read, Grep, Glob`, and block Bash, Write, Edit and web tools. Claude Code enforces this, not a prompt. |
| The orchestrator cannot browse | The skill sets `disallowed-tools: WebFetch, WebSearch`. |
| Only bundled scripts run | Bash is pre-approved only for `python3 -I` on the skill's own scripts and read-only `git` commands. |
| Scripts never execute target code | Stdlib only, `python3 -I`, no imports from the target, no symlink escapes. Covered by tests. |
| Repo instructions are data | Every agent treats repo text as data and reports prompt injection as a finding. An eval case checks this. |
| Network is opt-in | See [PRIVACY.md](PRIVACY.md). |

## What PYA cannot protect you from

Opening an untrusted repository in Claude Code at all can be risky. Its own `.claude/settings.json`,
hooks and `.mcp.json` may load once you trust the folder, before PYA runs.

For repositories you do not trust:
- open them in a container, devcontainer or VM;
- do not accept the workspace trust prompt for them;
- run PYA from a parent directory, pointing it at the path.

## Verifying a release

Releases are published as immutable GitHub releases. Verify one with the GitHub CLI:

```bash
gh release verify v2.0.0 --repo AgriciDaniel/claude-cybersecurity
gh release verify-asset v2.0.0 pya-2.0.0.zip --repo AgriciDaniel/claude-cybersecurity
```
