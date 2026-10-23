"""The monthly feed validates, cites sources and stores no live malicious links."""

import copy
import glob
import json
import os
import re

import pytest

from conftest import FEED, FEED_DIR, REPO, nonvacuous, run_script

DIGEST = os.path.join(os.path.dirname(os.path.dirname(REPO)),
                      "Developer and Infrastructure Security Digest_ Sept 23 to Oct 23, 2026 (v2, verified).md")


def feeds():
    return sorted(glob.glob(os.path.join(FEED_DIR, "20*.json")))


def test_every_feed_validates():
    files = feeds()
    nonvacuous(len(files), "feed files")
    code, out, _ = run_script("validate_feed.py", *files)
    assert code == 0, out
    assert out["ok"] is True
    for r in out["results"]:
        nonvacuous(r["entries"], f"entries in {r['file']}")


def test_feed_against_json_schema(feed):
    jsonschema = pytest.importorskip("jsonschema")
    with open(os.path.join(FEED_DIR, "schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator(schema).validate(feed)


def test_header_dates(feed):
    assert feed["feed"] == "2026-10"
    assert feed["as_of"] == "2026-10-23"
    assert feed["expires"] == "2026-11-27"
    assert feed["source_digest"].startswith("Developer and Infrastructure Security Digest")


def test_kev_only_where_digest_says(feed):
    kev = sorted(e["package"] for e in feed["entries"] if e["kev"])
    assert kev == ["plexinc/pms-docker", "wordpress"]


def test_expected_items_present(feed):
    pkgs = {(e.get("ecosystem"), e.get("package")) for e in feed["entries"]}
    for item in [("PyPI", "litellm"), ("npm", "tensorlake"), ("npm", "@subql/common"), ("npm", "@apexacc/cli"),
                 ("npm", "imgdecode"), ("npm", "next"), ("npm", "sharp"), ("npm", "undici"), ("runtime", "node"),
                 ("npm", "@modelcontextprotocol/sdk"), ("PyPI", "mcp"), ("PyPI", "pip"), ("PyPI", "certifi"),
                 ("PyPI", "uv"), ("PyPI", "conda"), ("runtime", "php"), ("WordPress", "wordpress"),
                 ("WordPress", "updraftplus"), ("WordPress", "ninja-forms"), ("WordPress", "woo-product-bundle"),
                 ("WordPress", "elementor"), ("WordPress", "bricksforge"), ("npm", "n8n"),
                 ("Docker", "gitroomhq/postiz-app"), ("Docker", "gitlab/gitlab-ce"), ("Docker", "gitlab/gitlab-ee"),
                 ("runtime", "docker"), ("runtime", "podman"), ("Go", "github.com/ovh/ovhcloud-cli")]:
        assert item in pkgs, item
    ioc_values = " ".join(i["value"] for e in feed["entries"] for i in e.get("iocs", []))
    for needle in ["cook.pth", "sitecustomize.py", "litellm-1.107.0.dist-info", "/tmp/remote_code_loader.lock",
                   "gh-token-monitor", "_sync_token", "Site Health Cache", "wp-smart-thumbnails", "fz_emer_done_v1",
                   "wp-pear-rce-flag.php", "poc87902.php", "microsoftvs", "cosmic-themes", "solidity",
                   "security-audit", "emSign"]:
        assert needle in ioc_values, needle


def test_no_live_malicious_links(feed):
    text = json.dumps(feed)
    for bad in ["litellm.dev", "imgcdn1.com", "193.32.204.199"]:
        assert bad not in text, f"{bad} stored as a plain, linkable value"
    for e in feed["entries"]:
        for ioc in e.get("iocs", []):
            assert ioc["type"] not in ("domain", "ip")
            assert "://" not in ioc["note"]


def test_regex_iocs_still_match_the_indicator(feed):
    rx = {i["value"]: re.compile(i["value"]) for e in feed["entries"] for i in e.get("iocs", []) if i["type"] == "regex"}
    nonvacuous(len(rx), "regex IOCs")
    samples = {
        "litellm\\.dev/healthcheck": "POST " + "litellm" + "." + "dev/healthcheck",
        "193\\.32\\.204\\.199": "curl -d @- http://" + "193.32.204" + ".199/x",
        "imgcdn1\\.com": "src=//" + "imgcdn1" + ".com/a.js",
    }
    for pattern, sample in samples.items():
        assert rx[pattern].search(sample)


def test_postiz_uses_real_fix_not_typo(feed):
    postiz = [e for e in feed["entries"] if e.get("package") == "gitroomhq/postiz-app"][0]
    assert postiz["fixed_in"] == ["2.24.0"]


def test_sources_come_from_digest(feed):
    if not os.path.isfile(DIGEST):
        pytest.skip("digest file not available next to the repo")
    with open(DIGEST, encoding="utf-8") as fh:
        digest = fh.read()
    urls = set(re.findall(r"\]\((https://[^)\s]+)\)", digest))
    checked = 0
    for e in feed["entries"]:
        for s in e["sources"]:
            assert s in urls, f"{e['id']} source not in digest: {s}"
            checked += 1
    nonvacuous(checked, "sources")


def _bad_feed(tmp_path, mutate):
    with open(FEED, encoding="utf-8") as fh:
        doc = json.load(fh)
    mutate(doc)
    path = tmp_path / "2026-10.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("name,mutate,needle", [
    ("dup", lambda d: d["entries"].append(copy.deepcopy(d["entries"][0])), "duplicate id"),
    ("http", lambda d: d["entries"][0].update(sources=["http://example.invalid/x"]), "https"),
    ("nosrc", lambda d: d["entries"][0].update(sources=[]), "non-empty"),
    ("dates", lambda d: d.update(expires="2026-10-01"), "expires must be after"),
    ("enum", lambda d: d["entries"][0].update(severity="SEVERE"), "severity"),
    ("idpat", lambda d: d["entries"][0].update(id="PYA-26-10-1"), "id must match"),
    ("empty", lambda d: d.update(entries=[]), "zero entries"),
    ("ro", lambda d: d["entries"][0].update(response_order="panic"), "response_order"),
    ("extra", lambda d: d["entries"][0].update(foo=1), "unknown field"),
    ("dash", lambda d: d["entries"][0].update(title="a " + chr(0x2014) + " b"), "dash"),
    ("domain", lambda d: d["entries"][0]["iocs"].append({"type": "domain", "value": "x.example", "note": "n"}),
     "regex"),
    ("badre", lambda d: d["entries"][0]["iocs"].append({"type": "regex", "value": "(", "note": "n"}), "compile"),
])
def test_validator_rejects(tmp_path, name, mutate, needle):
    path = _bad_feed(tmp_path, mutate)
    code, out, _ = run_script("validate_feed.py", path)
    assert code == 1
    assert out["ok"] is False
    assert any(needle in err for err in out["results"][0]["errors"]), out["results"][0]["errors"]


def test_validator_usage_error():
    code, out, _ = run_script("validate_feed.py")
    assert code == 2 and out["error"] == "usage"
