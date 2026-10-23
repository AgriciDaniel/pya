"""update_kev imports a catalog into a slim snapshot; bad input fails cleanly."""

import json
import os

from conftest import FIXTURES, run_script

SAMPLE = os.path.join(FIXTURES, "kev", "kev-sample.json")


def test_import_from_file(tmp_path):
    out_path = tmp_path / "pya" / "kev.json"
    code, out, err = run_script("update_kev.py", "--from-file", SAMPLE, "--output", str(out_path))
    assert code == 0, err
    assert out["status"] == "updated" and out["count"] == 3
    assert out["catalogVersion"] == "0000.00.00-test"
    snap = json.loads(out_path.read_text())
    assert set(snap["cves"]) == {"CVE-2026-87902", "CVE-2026-96654", "CVE-2026-109383"}
    assert snap["dateReleased"].startswith("2026-10-21")
    code, out, _ = run_script("update_kev.py", "--from-file", SAMPLE, "--output", str(out_path))
    assert out["previous_catalogVersion"] == "0000.00.00-test"


def test_default_path_uses_xdg_cache(tmp_path):
    code, out, _ = run_script("update_kev.py", "--from-file", SAMPLE, env={"XDG_CACHE_HOME": str(tmp_path)})
    assert code == 0
    assert out["output"] == os.path.join(str(tmp_path), "pya", "kev.json")


def test_rejects_non_catalog(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"vulnerabilities": []}')
    code, out, _ = run_script("update_kev.py", "--from-file", str(bad), "--output", str(tmp_path / "k.json"))
    assert code == 1 and out["status"] == "failed"
    assert not (tmp_path / "k.json").exists()


def test_usage_error():
    code, out, _ = run_script("update_kev.py", "--bogus")
    assert code == 2
