"""A checker that inspects zero items must fail."""

import os
import subprocess
import sys

import pytest

from conftest import REPO, nonvacuous, run_script


def test_guard_fails_on_zero():
    with pytest.raises(AssertionError):
        nonvacuous(0, "items")
    with pytest.raises(AssertionError):
        nonvacuous(None, "items")
    assert nonvacuous(3, "items") == 3


def test_empty_feed_fails_validation(tmp_path):
    p = tmp_path / "2026-10.json"
    p.write_text('{"feed": "2026-10", "as_of": "2026-10-23", "expires": "2026-11-27", '
                 '"source_digest": "x", "entries": []}')
    code, out, _ = run_script("validate_feed.py", str(p))
    assert code == 1


def test_dash_check_fails_on_zero_files(tmp_path):
    proc = subprocess.run([sys.executable, "-I", os.path.join(REPO, "tests", "check_dashes.py"), str(tmp_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "zero files" in proc.stdout


def test_dash_check_finds_dash(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("bad " + chr(0x2014) + " dash\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", os.path.join(REPO, "tests", "check_dashes.py"), str(tmp_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "U+2014" in proc.stdout


def test_dash_check_repo_clean():
    proc = subprocess.run([sys.executable, "-I", os.path.join(REPO, "tests", "check_dashes.py"), REPO],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout


def test_score_without_agents_is_capped_and_unscored():
    code, out, _ = run_script("score.py", "-", stdin='{"agents": []}')
    assert code == 0
    assert out["overall"] is None and out["grade"] is None
    assert len(out["unreviewed"]) == 9
