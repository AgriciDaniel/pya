# Contributing to PYA

## Report a bug or a missed detection

- Security issues: use the private advisory form in [SECURITY.md](SECURITY.md), not a public issue.
- False positives and false negatives: open an issue with the code snippet, what PYA reported, and what you expected.

## Before you open a pull request

Run `make check`. It runs the script tests, feed validation, the seed-coverage test, the dash
check, shellcheck and `claude plugin validate . --strict`.

If your change affects what PYA reports, add or update an eval case in `evals/`; see
[evals/README.md](evals/README.md).

## Where things go

| Change | File |
|---|---|
| A permanent technique (how an attack works) | `skills/pya/references/` plus a seed in `skills/pya/references/seeds.json` with vulnerable and safe examples |
| A specific bad version, CVE or IOC from this month | `skills/pya/feed/YYYY-MM.json`, with a source URL for every entry (see `skills/pya/feed/README.md`) |
| A standard version or link | `skills/pya/references/standards.md` only |
| Agent behavior | `agents/<name>.md` (keep `tools: Read, Grep, Glob`) |
| Orchestration, scoring or report shape | `docs/architecture.md` first, then `SKILL.md`, `scripts/score.py` and `references/report-template.md` |

## Writing rules

- Never use em or en dashes. The dash check fails the build.
- Cite a URL for every dated fact.
- Keep `skills/pya/SKILL.md` under 500 lines.
- Use inert test fixtures only: documentation IP ranges (203.0.113.0/24), `.example.invalid` domains, and AWS example keys.
