"""Seed coverage: every seed matches its vulnerable examples and none of its safe ones."""

import re

import pytest

from conftest import load_module, nonvacuous

REQUIRED = {"id", "agent", "title", "regex", "file_glob", "attack", "cwe", "examples_vulnerable", "examples_safe"}
AGENTS = {"vuln-scanner", "authz-reviewer", "secret-scanner", "dependency-auditor", "iac-scanner", "threat-intel",
          "ai-code-auditor", "logic-reviewer", "agentic-auditor"}
ioc_scan = load_module("ioc_scan")


def seed_matches(seed, compiled, mode, example):
    if mode == "path":
        return bool(compiled.search(example))
    lines = example.split("\n")
    text = example
    lineno = load_module("_pya_common").line_index(text)
    return any(True for _ in ioc_scan.scan_text(compiled, mode, text, lines, lineno))


def all_seeds():
    import json
    from conftest import SEEDS
    with open(SEEDS, encoding="utf-8") as fh:
        return json.load(fh)["seeds"]


SEED_LIST = all_seeds()


def test_seed_file_is_not_empty():
    nonvacuous(len(SEED_LIST), "seeds")


def test_seed_shape():
    ids = set()
    for s in SEED_LIST:
        missing = REQUIRED - set(s)
        assert not missing, (s.get("id"), missing)
        assert s["id"] not in ids
        ids.add(s["id"])
        assert s["agent"] in AGENTS, s["id"]
        assert s.get("match_on", "line") in ("line", "file", "path")
        assert isinstance(s["file_glob"], list) and s["file_glob"]
        assert s["cwe"] is None or re.match(r"^CWE-\d+$", s["cwe"])
        assert s["attack"] is None or re.match(r"^T\d{4}(\.\d{3})?$", s["attack"])
        nonvacuous(len(s["examples_vulnerable"]), f"vulnerable examples in {s['id']}")
        nonvacuous(len(s["examples_safe"]), f"safe examples in {s['id']}")


def test_required_techniques_covered():
    ids = {s["id"] for s in SEED_LIST}
    for need in ["SEED-PTH-EXEC", "SEED-SITECUSTOMIZE", "SEED-CRED-STORE-READ", "SEED-SYSTEMD-USER-UNIT",
                 "SEED-TOKEN-GATED-WIPER", "SEED-PIPE-TO-SHELL", "SEED-B64-EXEC", "SEED-REVERSE-SHELL",
                 "SEED-USER-INI-PREPEND", "SEED-ARGC-ARGV-ON", "SEED-PEARCMD", "SEED-MATH-RANDOM-SECRET",
                 "SEED-GHA-EXPR-INJECTION", "SEED-PRT-HEAD-CHECKOUT", "SEED-ACTION-TAG-PIN",
                 "SEED-PERSIST-CREDENTIALS", "SEED-HIDDEN-UNICODE-TAGS", "SEED-CLAUDE-PERMISSIVE",
                 "SEED-CLAUDE-ALL-MCP", "SEED-MCP-LATEST", "SEED-VSCODE-FOLDEROPEN", "SEED-TLS-VERIFY-OFF",
                 "SEED-NODE-TLS-REJECT-0", "SEED-EMSIGN-BUNDLE"]:
        assert need in ids, need


def test_examples_are_inert():
    for s in SEED_LIST:
        for ex in s["examples_vulnerable"] + s["examples_safe"]:
            for host in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", ex):
                assert host.startswith(("203.0.113.", "127.", "0.0.0.0")), (s["id"], host)
            for dom in re.findall(r"https?://([^/\s'\"]+)", ex):
                assert dom.endswith("example.invalid") or dom.startswith(("203.0.113.", "127.")) \
                    or dom in ("registry.npmjs.org", "api.github.com"), (s["id"], dom)


@pytest.mark.parametrize("seed", SEED_LIST, ids=[s["id"] for s in SEED_LIST])
def test_seed_examples(seed):
    mode = seed.get("match_on", "line")
    compiled = re.compile(seed["regex"], re.M if mode in ("line", "file") else 0)
    checked = 0
    for ex in seed["examples_vulnerable"]:
        assert seed_matches(seed, compiled, mode, ex), f"{seed['id']} missed vulnerable example: {ex!r}"
        checked += 1
    for ex in seed["examples_safe"]:
        assert not seed_matches(seed, compiled, mode, ex), f"{seed['id']} matched safe example: {ex!r}"
        checked += 1
    nonvacuous(checked, f"examples for {seed['id']}")
