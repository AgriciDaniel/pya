# Privacy Policy

PYA runs inside your Claude Code session. It has no server, account, telemetry or analytics.

## What PYA does by default (offline)

- Reads files in the directory you ask it to audit.
- Runs its bundled Python scripts locally. They read files and print JSON, and they make no network calls.
- Runs osv-scanner, trufflehog, zizmor or semgrep only if you installed them yourself, and in offline mode unless you pass `--online`.
- Prints the report in your terminal. It writes a report file only if you ask it to.

Your code is processed by Claude within your existing Claude Code session. That is the same data
path as any other Claude Code request; see [Anthropic's privacy policy](https://www.anthropic.com/privacy).

## What changes with `--online` (opt-in)

| Tool | Service contacted | Data sent |
|---|---|---|
| osv-scanner (online lookups) | osv.dev (Google) | Package names and versions from your lockfiles |
| trufflehog (verification) | The provider of each detected secret (for example AWS, GitHub, Anthropic) | The candidate secret, to test whether it is live |
| zizmor (online audits) | api.github.com | Names of the actions and repositories your workflows use, to check their tags and advisories; uses a GitHub token from your environment if one is set |
| update_kev.py (only when you ask for a KEV refresh) | cisa.gov | A plain download of the public KEV catalog; nothing about your code |

PYA tells you which of these will run before it runs them. Without `--online`, the scanners stay offline, and the KEV refresh runs only when you ask for it.

## What PYA never does

- Send your code anywhere except through your own Claude Code session.
- Install software, run your project's code, run your package manager, or modify your files.
- Store data outside your machine. The KEV cache lives in `~/.cache/pya/`.

**Last updated:** 2026-10-23
