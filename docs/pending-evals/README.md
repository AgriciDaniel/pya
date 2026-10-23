# Pending eval cases

These cases sit outside `evals/`, so the default `claude plugin eval` run skips them. Four have
prompts and graders but no fixture yet. `diff-mode` is complete but cannot pass under the eval
sandbox, which blocks running git.

| Case | What the fixture needs to contain |
|---|---|
| litellm-pth | A Python environment with startup-hook indicators and the malicious litellm pin from the feed |
| token-wiper | An npm package whose install step shows the token-monitor persistence indicators from the feed |
| wp-backdoor | A WordPress tree with the `.user.ini` prepend and database-trigger indicators |
| hostile-agent-config | A repo with permissive `.claude/settings.json` hooks and an unpinned `.mcp.json` server. The sandbox masks these paths at the workspace root, so build them in a subdirectory and point the prompt at it |

A maintainer should write each `fixture.sh` by hand, following the rules in `evals/README.md`:
inert content, documentation IP ranges, no working payloads. Then move the case back into `evals/`.

## diff-mode

The fixture and graders work, but the eval sandbox in Claude Code 2.1.309 refuses to run
`/usr/bin/git` (exit 126, "Permission denied"). PYA then stops as designed and offers
`--scope full`, so the report graders fail. Test `--scope diff` by hand in a normal session, and
move the case back into `evals/` when the eval sandbox allows git.
