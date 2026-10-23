"""inventory lists manifests, lockfiles, IaC, CI and agent config files."""

import os

import pytest

from conftest import FIXTURES, REPO, nonvacuous, run_script, write


def test_fixture_inventory():
    code, out, err = run_script("inventory.py", FIXTURES, "--json")
    assert code == 0, err
    nonvacuous(out["files_total"], "files")
    nonvacuous(out["coverage"]["files_in_scope"], "files in scope")
    assert "deps/npm-v3/package-lock.json" in out["lockfiles"]
    assert "deps/pnpm/pnpm-lock.yaml" in out["lockfiles"]
    assert "deps/bun/bun.lock" in out["lockfiles"]
    assert "deps/python/requirements.txt" in out["manifests"]
    assert "containers/Dockerfile" in out["iac"]
    assert "containers/docker-compose.yml" in out["iac"]
    assert "runtime/.nvmrc" in out["runtime_pins"]
    assert out["wordpress"]["core"] == "wordpress/wp-includes/version.php"
    assert out["wordpress"]["plugins"] >= 4


def test_agent_surface(tmp_path):
    write(tmp_path, ".claude/settings.json", "{}")
    write(tmp_path, ".mcp.json", "{}")
    write(tmp_path, "CLAUDE.md", "# rules\n")
    write(tmp_path, ".vscode/tasks.json", "{}")
    write(tmp_path, ".github/workflows/ai.yml", "jobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n")
    write(tmp_path, "package.json", '{"dependencies": {"@anthropic-ai/sdk": "1.0.0"}}')
    write(tmp_path, "app.py", "print(1)\n")
    code, out, _ = run_script("inventory.py", str(tmp_path))
    assert code == 0
    for f in (".claude/settings.json", ".mcp.json", "CLAUDE.md", ".vscode/tasks.json"):
        assert f in out["agent_config"], f
    assert out["ai_ci_actions"][0]["uses"].startswith("anthropics/claude-code-action")
    assert "@anthropic-ai/sdk" in out["llm_sdks"]
    assert out["agentic_surface"] is True
    assert out["languages"]["Python"] == 1


def test_no_agentic_surface(tmp_path):
    write(tmp_path, "main.go", "package main\n")
    code, out, _ = run_script("inventory.py", str(tmp_path))
    assert out["agentic_surface"] is False


def test_skips_vendor_dirs(tmp_path):
    write(tmp_path, "node_modules/x/package.json", "{}")
    write(tmp_path, ".venv/lib/a.py", "x")
    write(tmp_path, "src/a.py", "x")
    code, out, _ = run_script("inventory.py", str(tmp_path))
    assert out["files_total"] == 1
    assert out["skipped_dirs"] == {"node_modules": 1, ".venv": 1}


def test_runs_on_repo_itself():
    code, out, _ = run_script("inventory.py", REPO)
    assert code == 0
    assert any(p.startswith(".github/workflows/") for p in out["ci"])


def test_usage_error():
    code, out, _ = run_script("inventory.py")
    assert code == 2 and out["error"] == "usage"
    code, out, _ = run_script("inventory.py", os.path.join(FIXTURES, "clean", "app.py"))
    assert code == 2


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read mode 000 files")
def test_empty_or_unreadable_agent_config_is_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".mcp.json").write_text("")
    blocked = tmp_path / ".claude" / "settings.json"
    blocked.write_text("{}")
    blocked.chmod(0)
    try:
        code, out, err = run_script("inventory.py", str(tmp_path))
    finally:
        blocked.chmod(0o600)
    assert code == 0, err
    assert set(out["agent_config_empty_or_unreadable"]) == {".mcp.json", ".claude/settings.json"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_special_files_are_not_counted(tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n")
    (tmp_path / ".claude").mkdir()
    os.mkfifo(tmp_path / ".claude" / "settings.json")
    code, out, err = run_script("inventory.py", str(tmp_path))
    assert code == 0, err
    assert out["files_total"] == 1
    assert out["special_files"] == [".claude/settings.json"]
    assert out["counts"]["agent_config"] == 0
