"""run_tools reports not_installed cleanly, parses tool output and masks secrets."""

import json
import os
import shutil
import stat

from conftest import FIXTURES, run_script, write

TOOLS = ("osv-scanner", "trufflehog", "zizmor", "semgrep")


def fake_tool(bindir, name, body):
    path = write(bindir, name, "#!/bin/sh\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def test_not_installed(tmp_path):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    code, out, err = run_script("run_tools.py", FIXTURES, "--json", env={"PATH": str(empty)})
    assert code == 0, err
    for t in TOOLS:
        assert out["tools"][t]["status"] == "not_installed"
        assert "never installs" in out["tools"][t]["reason"]
    assert out["ran"] == [] and out["mode"] == "offline"


def test_fake_tools(tmp_path):
    bindir = tmp_path / "bin"
    secret = "sk-ant-" + "api03-" + "Z" * 40
    rec = {"DetectorName": "Anthropic", "Verified": False, "Raw": secret,
           "SourceMetadata": {"Data": {"Filesystem": {"file": "/x/app/.env", "line": 3}}}}
    fake_tool(bindir, "trufflehog", f"echo '{json.dumps(rec)}'\necho 'log line' 1>&2\nexit 0\n")
    fake_tool(bindir, "zizmor", "echo 'boom: unexpected' 1>&2\nexit 2\n")
    fake_tool(bindir, "osv-scanner", "exit 0\n")
    fake_tool(bindir, "semgrep", "exit 0\n")
    env = {"PATH": str(bindir), "HOME": str(tmp_path / "home"), "XDG_CACHE_HOME": str(tmp_path / "cache")}
    env.pop("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", None)
    code, out, err = run_script("run_tools.py", FIXTURES, env=env)
    assert code == 0, err
    th = out["tools"]["trufflehog"]
    assert th["status"] == "ran" and "--no-verification" in th["command"]
    assert th["summary"]["results"] == 1
    assert secret not in json.dumps(out)
    assert th["summary"]["items"][0]["redacted"] == secret[:4] + "..." + secret[-4:]
    assert out["tools"]["zizmor"]["status"] == "failed"
    assert out["tools"]["osv-scanner"]["status"] == "not_run"
    assert "local OSV database" in out["tools"]["osv-scanner"]["reason"]
    assert out["tools"]["semgrep"]["status"] == "not_run"


def test_online_flag_enables_verification(tmp_path):
    bindir = tmp_path / "bin"
    fake_tool(bindir, "trufflehog", "exit 0\n")
    code, out, _ = run_script("run_tools.py", FIXTURES, "--online", "--only", "trufflehog",
                              env={"PATH": str(bindir)})
    th = out["tools"]["trufflehog"]
    assert th["mode"] == "online" and "--no-verification" not in th["command"]
    assert out["tools"]["zizmor"]["status"] == "not_run"


def test_tool_inside_target_is_refused(tmp_path):
    target = tmp_path / "repo"
    fake_tool(target / "bin", "zizmor", "echo '[]'\nexit 0\n")
    code, out, _ = run_script("run_tools.py", str(target), "--only", "zizmor",
                              env={"PATH": str(target / "bin")})
    assert out["tools"]["zizmor"]["status"] == "not_run"
    assert "inside the target" in out["tools"]["zizmor"]["reason"]


def test_timeout(tmp_path):
    bindir = tmp_path / "bin"
    fake_tool(bindir, "zizmor", f"{shutil.which('sleep')} 5\n")
    code, out, _ = run_script("run_tools.py", FIXTURES, "--only", "zizmor", "--timeout", "1",
                              env={"PATH": str(bindir)})
    assert out["tools"]["zizmor"]["status"] == "failed"
    assert "timed out" in out["tools"]["zizmor"]["reason"]


def test_usage_error():
    code, out, _ = run_script("run_tools.py", FIXTURES, "--only", "nmap")
    assert code == 2
