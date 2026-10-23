#!/usr/bin/env python3
"""PYA inventory: what is in the target repo, for scoping and coverage.

Usage: python3 -I inventory.py <target> [--json] [--max-list N]

Lists languages by extension, manifests, lockfiles, IaC and CI files,
agent configuration files, runtime pins, symlinks (and whether they escape
the target) and totals for the coverage table. Reads only file names, plus
the first bytes of CI workflows and manifests to spot AI CI actions and LLM
SDKs. Never executes or imports anything from the target. Output is compact
JSON on stdout.
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

LANG_BY_EXT = {
    ".py": "Python", ".pyi": "Python", ".js": "JavaScript", ".cjs": "JavaScript", ".mjs": "JavaScript",
    ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".cts": "TypeScript", ".mts": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".phtml": "PHP", ".inc": "PHP",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".swift": "Swift",
    ".m": "Objective-C", ".mm": "Objective-C", ".c": "C", ".h": "C/C++ header", ".cc": "C++", ".cpp": "C++",
    ".cxx": "C++", ".hpp": "C++", ".cs": "C#", ".fs": "F#", ".vb": "Visual Basic", ".sh": "Shell",
    ".bash": "Shell", ".zsh": "Shell", ".ps1": "PowerShell", ".psm1": "PowerShell", ".pl": "Perl",
    ".lua": "Lua", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".clj": "Clojure",
    ".r": "R", ".jl": "Julia", ".sol": "Solidity", ".vue": "Vue", ".svelte": "Svelte", ".astro": "Astro",
    ".html": "HTML", ".htm": "HTML", ".sql": "SQL", ".tf": "HCL", ".hcl": "HCL", ".bicep": "Bicep",
    ".zig": "Zig", ".nim": "Nim", ".groovy": "Groovy",
}
CONFIG_EXT = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".env", ".properties"}

MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
    "composer.json", "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle", "build.gradle.kts",
    "packages.config", "mix.exs", "pubspec.yaml", "Package.swift", "deno.json", "deno.jsonc",
    "environment.yml", "environment.yaml",
}
MANIFEST_GLOBS = ["requirements*.txt", "requirements/*.txt", "*.csproj", "*.fsproj", "*.gemspec"]
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
    "poetry.lock", "uv.lock", "pylock.toml", "Pipfile.lock", "pdm.lock", "composer.lock", "go.sum",
    "Cargo.lock", "Gemfile.lock", "packages.lock.json", "gradle.lockfile", "mix.lock", "pubspec.lock",
    "Package.resolved", "deno.lock", "conda-lock.yml",
}
LOCK_GLOBS = ["pylock.*.toml"]
IAC_GLOBS = [
    "Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile", "Containerfile.*", "docker-compose*.yml",
    "docker-compose*.yaml", "compose*.yml", "compose*.yaml", "*.tf", "*.tfvars", "*.bicep", "Chart.yaml",
    "kustomization.yaml", "kustomization.yml", "php.ini", "*.php.ini", ".user.ini", ".htaccess",
    "nginx.conf", "*.nginx.conf", "daemon.json", "ssh_config", "sshd_config", "Vagrantfile",
    "serverless.yml", "serverless.yaml", "vercel.json", "netlify.toml", "fly.toml", "railway.json",
    "railway.toml", "render.yaml", "app.yaml", "Procfile", "wp-config.php", "*.service",
    "k8s/*.yaml", "k8s/*.yml", "**/k8s/*.yaml", "**/k8s/*.yml", "kubernetes/*.yaml", "**/helm/**/*.yaml",
    "template.yaml", "*.template.json", "cloudformation/*.yaml", "cloudformation/*.json",
]
CI_GLOBS = [
    ".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/**/action.yml",
    ".github/actions/**/action.yaml", "action.yml", "action.yaml", ".gitlab-ci.yml", ".circleci/config.yml",
    "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml", ".travis.yml", ".drone.yml",
    ".buildkite/*.yml", ".github/dependabot.yml", ".woodpecker.yml", ".woodpecker/*.yml",
    "cloudbuild.yaml", "buildspec.yml",
]
AGENT_GLOBS = [
    ".claude/settings.json", ".claude/settings.local.json", ".claude/settings*.json", ".claude/agents/**",
    ".claude/skills/**", ".claude/commands/**", ".claude/hooks/**", ".mcp.json", "**/.mcp.json",
    "CLAUDE.md", "**/CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "**/AGENTS.md", "GEMINI.md",
    ".cursor/**", ".cursorrules", ".windsurfrules", ".vscode/mcp.json", ".vscode/tasks.json",
    ".vscode/extensions.json", ".vscode/settings.json", ".vscode/launch.json", "*.code-workspace",
    ".github/mcp.json", ".github/skills/**", ".github/copilot-instructions.md", ".github/instructions/**",
    ".github/prompts/**", ".codex/**", ".gemini/**", ".claude-plugin/**", "hooks/hooks.json",
    "**/hooks/hooks.json", "skills/**/SKILL.md", "agents/*.md", "claude_desktop_config.json", "mcp.json",
]
RUNTIME_PINS = {".nvmrc", ".node-version", ".python-version", ".tool-versions", "runtime.txt",
                ".php-version", ".ruby-version", ".go-version", ".bun-version", ".terraform-version"}
AI_CI_RE = re.compile(
    r"uses:\s*['\"]?(?:anthropics/claude-code-action|anthropics/claude-code-base-action|openai/codex-action|"
    r"google-github-actions/run-gemini-cli|github/copilot|[\w.\-]+/[\w.\-]*(?:claude|codex|gemini|copilot|"
    r"openhands|aider)[\w.\-]*)@",
    re.I,
)
LLM_SDK_RE = re.compile(
    r"(?i)[\"'\s/=^](?:@anthropic-ai/sdk|@anthropic-ai/claude-agent-sdk|@anthropic-ai/claude-code|anthropic|"
    r"openai|@openai/agents|langchain[\w\-]*|@langchain/[\w\-]+|llama[-_]index|litellm|"
    r"@modelcontextprotocol/sdk|mcp|fastmcp|google-genai|@google/genai|google-generativeai|ai|@ai-sdk/[\w\-]+|"
    r"cohere|mistralai|ollama|crewai|autogen|pydantic-ai|transformers|vllm|groq)(?=[\"'\s=<>~^!@\[:,]|$)"
)


def matches_any(rel: str, globs) -> bool:
    return any(C.glob_match(rel, g) for g in globs)


def scan(target: str, max_list: int) -> dict:
    stats: dict = {}
    languages: dict = {}
    buckets = {k: [] for k in ("manifests", "lockfiles", "iac", "ci", "agent_config", "runtime_pins")}
    counts = {k: 0 for k in buckets}
    ai_ci = []
    llm_sdks = set()
    files_total = 0
    bytes_total = 0
    in_scope = 0
    too_large = 0
    wordpress = {"core": None, "plugins": 0, "themes": 0}
    agent_config_unreadable = []

    def add(bucket: str, rel: str):
        counts[bucket] += 1
        if len(buckets[bucket]) < max_list:
            buckets[bucket].append(rel)

    for rel, abspath, _ in C.walk(target, stats):
        files_total += 1
        size = C.file_size(abspath)
        bytes_total += max(size, 0)
        name = rel.rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()
        reviewable = False
        lang = LANG_BY_EXT.get(ext)
        if lang:
            languages[lang] = languages.get(lang, 0) + 1
            reviewable = True
        if name in MANIFESTS or matches_any(rel, MANIFEST_GLOBS):
            add("manifests", rel)
            reviewable = True
            if name in ("package.json", "pyproject.toml", "Pipfile", "composer.json", "go.mod") or name.startswith("requirements"):
                text = C.read_text(target, abspath, 512 * 1024)
                if text:
                    for m in LLM_SDK_RE.finditer(text):
                        llm_sdks.add(m.group(0).strip("\"'\t\n /=^").lower())
        if name in LOCKFILES or matches_any(rel, LOCK_GLOBS):
            add("lockfiles", rel)
            reviewable = True
        if matches_any(rel, IAC_GLOBS):
            add("iac", rel)
            reviewable = True
        if matches_any(rel, CI_GLOBS):
            add("ci", rel)
            reviewable = True
            if rel.startswith(".github/"):
                text = C.read_text(target, abspath, 512 * 1024)
                if text:
                    for m in AI_CI_RE.finditer(text):
                        if len(ai_ci) < max_list:
                            ai_ci.append({"file": rel, "uses": m.group(0).split(":", 1)[1].strip(" '\"@")})
        if matches_any(rel, AGENT_GLOBS):
            add("agent_config", rel)
            if size == 0 or not os.access(abspath, os.R_OK):
                # Empty or unreadable config (a sandbox can mask these): report it, never treat it as clean.
                agent_config_unreadable.append(rel)
            reviewable = True
        if name in RUNTIME_PINS:
            add("runtime_pins", rel)
            reviewable = True
        if not reviewable and ext in CONFIG_EXT:
            reviewable = True
        if "/wp-includes/version.php" in "/" + rel:
            wordpress["core"] = rel
        if re.search(r"(?:^|/)wp-content/plugins/[^/]+/[^/]+\.php$", rel):
            wordpress["plugins"] += 1
        if re.search(r"(?:^|/)wp-content/themes/[^/]+/style\.css$", rel):
            wordpress["themes"] += 1
        if size > C.DEFAULT_MAX_BYTES:
            too_large += 1
        if reviewable:
            in_scope += 1

    symlinks = stats.get("symlinks", [])
    return {
        "tool": "inventory",
        "target": target,
        "files_total": files_total,
        "bytes_total": bytes_total,
        "languages": dict(sorted(languages.items(), key=lambda kv: -kv[1])),
        **buckets,
        "counts": counts,
        "ai_ci_actions": ai_ci,
        "llm_sdks": sorted(llm_sdks),
        "agent_config_empty_or_unreadable": agent_config_unreadable[:max_list],
        "agentic_surface": bool(counts["agent_config"] or ai_ci or llm_sdks),
        "wordpress": wordpress,
        "symlinks": symlinks[:max_list],
        "symlinks_escaping": [s["path"] for s in symlinks if s["escapes"]][:max_list],
        "skipped_dirs": stats.get("skipped_dirs", {}),
        # Devices and FIFOs: not counted. Inside a sandbox these are usually masked dotfiles.
        "special_files": stats.get("special_files", [])[:max_list],
        "coverage": {
            "files_in_scope": in_scope,
            "files_too_large": too_large,
            "max_file_bytes": C.DEFAULT_MAX_BYTES,
            "truncated": stats.get("truncated", False),
        },
        "lists_capped_at": max_list,
    }


def main(argv) -> int:
    args = [a for a in argv if a != "--json"]
    max_list = 500
    if "--max-list" in args:
        i = args.index("--max-list")
        try:
            max_list = int(args[i + 1])
        except (IndexError, ValueError):
            raise C.UsageError("--max-list needs an integer")
        del args[i:i + 2]
    if len(args) != 1 or args[0].startswith("-"):
        raise C.UsageError("usage: inventory.py <target> [--json] [--max-list N]")
    target = C.resolve_target(args[0])
    C.emit(scan(target, max_list))
    return 0


if __name__ == "__main__":
    C.run_main(main)
