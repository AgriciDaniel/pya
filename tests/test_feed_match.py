"""feed_match finds known-bad pins in every parser fixture and ignores fixed versions."""

import json
import os

import pytest

from conftest import FIXTURES, load_module, nonvacuous, run_script, write

fm = load_module("feed_match")


@pytest.fixture(scope="module")
def result():
    code, out, err = run_script("feed_match.py", FIXTURES, "--json", "--kev", "/nonexistent/kev.json")
    assert code == 0, err
    return out


def hits(result):
    return {(m["package"], m["file"]) for m in result["matches"]}


def ids(result, file):
    return {m["feed_id"] for m in result["matches"] if m["file"] == file}


def test_inspected_something(result):
    nonvacuous(result["inspected"]["files"], "files")
    nonvacuous(result["inspected"]["packages"], "packages")
    nonvacuous(result["inspected"]["feed_entries"], "feed entries")


def test_feed_header(result):
    f = result["feed"]
    assert f["feed"] == "2026-10" and f["age_days"] == 0 and f["stale"] is False
    assert f["header"] == "Threat feed: 2026-10 (as of 2026-10-23, 0 days old)"


EXPECTED = [
    ("next", "deps/npm-v3/package-lock.json"),
    ("tensorlake", "deps/npm-v3/package-lock.json"),
    ("@modelcontextprotocol/sdk", "deps/npm-v3/package-lock.json"),
    ("undici", "deps/npm-v3/package-lock.json"),  # nested 7.29.0 copy
    ("@subql/common", "deps/npm-v1/npm-shrinkwrap.json"),
    ("undici", "deps/npm-v1/npm-shrinkwrap.json"),
    ("sharp", "deps/npm-v1/npm-shrinkwrap.json"),
    ("@apexacc/cli", "deps/pnpm/pnpm-lock.yaml"),
    ("next", "deps/pnpm/pnpm-lock.yaml"),
    ("imgdecode", "deps/pnpm/pnpm-lock.yaml"),
    ("undici", "deps/yarn-classic/yarn.lock"),
    ("sharp", "deps/yarn-berry/yarn.lock"),
    ("n8n", "deps/yarn-berry/yarn.lock"),
    ("@modelcontextprotocol/sdk", "deps/bun/bun.lock"),
    ("imgdecode", "deps/bun/bun.lock"),
    ("tensorlake", "deps/package-json/package.json"),
    ("next", "deps/package-json/package.json"),
    ("node", "deps/package-json/package.json"),
    ("litellm", "deps/python/requirements.txt"),
    ("pip", "deps/python/requirements.txt"),
    ("mcp", "deps/python/requirements.txt"),
    ("uv", "deps/python/requirements-dev.txt"),
    ("litellm", "deps/poetry/poetry.lock"),
    ("certifi", "deps/poetry/poetry.lock"),
    ("mcp", "deps/uv/uv.lock"),
    ("sigstore", "deps/pylock/pylock.toml"),
    ("certifi", "deps/pipfile/Pipfile.lock"),
    ("updraftplus", "deps/composer/composer.lock"),
    ("wordpress", "deps/composer/composer.lock"),
    ("wordpress", "wordpress/wp-includes/version.php"),
    ("ninja-forms", "wordpress/wp-content/plugins/ninja-forms/ninja-forms.php"),
    ("bricksforge", "wordpress/wp-content/plugins/bricksforge/bricksforge.php"),
    ("elementor", "wordpress/wp-content/plugins/elementor/elementor.php"),
    ("node", "containers/Dockerfile"),
    ("php", "containers/Dockerfile"),
    ("python", "containers/Dockerfile"),
    ("php", "containers/Containerfile"),
    ("gitlab/gitlab-ee", "containers/docker-compose.yml"),
    ("gitroomhq/postiz-app", "containers/docker-compose.yml"),
    ("berriai/litellm", "containers/docker-compose.yml"),
    ("cloudflare/cloudflared", "containers/docker-compose.yml"),
    ("node", "runtime/.nvmrc"),
    ("php", "runtime/.tool-versions"),
    ("node", "runtime/sub/.node-version"),
    ("github.com/ovh/ovhcloud-cli", "runtime/go.mod"),
]


@pytest.mark.parametrize("pkg,file", EXPECTED)
def test_known_bad_found(result, pkg, file):
    assert (pkg, file) in hits(result), f"{pkg} not matched in {file}"


NOT_EXPECTED = [
    ("sharp", "deps/npm-v3/package-lock.json"),        # 0.35.5 fixed
    ("@anthropic-ai/claude-code", "deps/npm-v3/package-lock.json"),  # 2.1.309 fixed
    ("undici", "deps/pnpm/pnpm-lock.yaml"),            # 8.12.2 fixed
    ("sharp", "deps/pnpm/pnpm-lock.yaml"),
    ("next", "deps/yarn-classic/yarn.lock"),           # 16.4.1 fixed
    ("undici", "deps/bun/bun.lock"),
    ("sharp", "deps/package-json/package.json"),       # ^0.35.5
    ("left-pad", "deps/package-json/package.json"),
    ("certifi", "deps/python/requirements.txt"),       # 2026.10.19 fixed
    ("conda", "deps/python/requirements-dev.txt"),     # 26.9.4 fixed
    ("requests", "deps/python/requirements.txt"),
    ("pip", "deps/uv/uv.lock"),                        # 26.2.2 fixed
    ("certifi", "deps/pylock/pylock.toml"),
    ("litellm", "deps/pipfile/Pipfile.lock"),          # 1.106.2 is the safe pin
    ("elementor", "deps/composer/composer.lock"),      # 4.3.2 fixed
    ("updraftplus", "wordpress/wp-content/plugins/updraftplus/updraftplus.php"),  # 1.26.13
    ("woo-product-bundle", "wordpress/wp-content/plugins/woo-product-bundle/readme.txt"),  # 8.6.7
    ("n8nio/n8n", "containers/docker-compose.yml"),    # 2.44.1 fixed
    ("plexinc/pms-docker", "containers/docker-compose.yml"),
    ("node", "containers/docker-compose.yml"),         # 22.23.4 fixed
    ("docker", "containers/Dockerfile"),               # 29.9.2 fixed
    ("node", "runtime/.tool-versions"),                # 24.22.1 fixed
    ("php", "deps/composer/composer.json"),            # ">=8.1" is a compatibility range, not a pin
]


@pytest.mark.parametrize("pkg,file", NOT_EXPECTED)
def test_fixed_versions_ignored(result, pkg, file):
    assert (pkg, file) not in hits(result), f"{pkg} wrongly matched in {file}"


def test_clean_tree_has_zero_matches():
    code, out, _ = run_script("feed_match.py", os.path.join(FIXTURES, "clean"), "--kev", "/nonexistent")
    assert code == 0
    nonvacuous(out["inspected"]["packages"], "packages in clean tree")
    assert out["matches"] == []


def test_broken_files_are_reported_not_fatal(result):
    errs = {e["file"] for e in result["errors"]}
    assert "broken/package-lock.json" in errs
    assert "broken/poetry.lock" in errs


def test_match_fields(result):
    m = [x for x in result["matches"] if x["package"] == "tensorlake" and x["file"].endswith("package-lock.json")][0]
    assert m["feed_id"].startswith("PYA-2026-10-")
    assert m["malicious"] is True
    assert m["response_order"] == "tensorlake-wiper"
    assert m["line"] > 0 and m["sources"]
    assert m["why"].startswith("exact match")
    wp = [x for x in result["matches"] if x["package"] == "wordpress"]
    assert wp and all(x["kev"] for x in wp)
    assert result["kev_matches"] >= 2


def test_floating_tag_is_low_confidence(result):
    m = [x for x in result["matches"] if x["file"] == "runtime/sub/.node-version"][0]
    assert m["match_confidence"] == "low" and "floating" in m["why"]
    eol = [x for x in result["matches"] if x["file"] == "containers/Dockerfile" and x["package"] == "node"
           and x["line"] == 2][0]
    assert eol["match_confidence"] == "high" and "whole 20 line" in eol["why"]


def test_stale_feed_flag():
    code, out, _ = run_script("feed_match.py", os.path.join(FIXTURES, "clean"), env={"PYA_TODAY": "2026-12-15"})
    assert out["feed"]["stale"] is True and out["feed"]["age_days"] == 53
    assert out["feed"]["expired"] is True


def test_kev_cache_flags_alias(tmp_path):
    kev = tmp_path / "kev.json"
    code, out, _ = run_script("update_kev.py", "--from-file", os.path.join(FIXTURES, "kev", "kev-sample.json"),
                              "--output", str(kev))
    assert code == 0 and out["status"] == "updated"
    code, out, _ = run_script("feed_match.py", os.path.join(FIXTURES, "deps", "yarn-classic"), "--kev", str(kev))
    assert out["kev_cache"]["present"] is True
    undici = [m for m in out["matches"] if m["package"] == "undici"][0]
    assert undici["kev"] is True and undici["kev_cache_hits"] == ["CVE-2026-109383"]


def test_explicit_feed_path(tmp_path):
    from conftest import FEED
    code, out, _ = run_script("feed_match.py", os.path.join(FIXTURES, "clean"), "--feed", FEED)
    assert code == 0 and out["feed"]["file"] == "2026-10.json"


def test_usage_errors(tmp_path):
    code, out, _ = run_script("feed_match.py")
    assert code == 2
    code, out, _ = run_script("feed_match.py", str(tmp_path / "missing"))
    assert code == 2


# ---- parser unit tests ----------------------------------------------------

def test_pnpm_v5_key():
    pk = fm.parse_pnpm_lock("lockfileVersion: 5.4\n\npackages:\n\n  /undici/6.0.0_abc:\n    resolution: {}\n", "x")
    assert [(p.name, p.version) for p in pk] == [("undici", "6.0.0")]


def test_scoped_split():
    assert fm.split_name_version("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")
    assert fm.split_name_version("pkg") == (None, None)


def test_strip_jsonc_keeps_strings():
    text = '{"a": "http://x//y", /* c */ "b": [1,2,],}'
    assert json.loads(fm.strip_jsonc(text)) == {"a": "http://x//y", "b": [1, 2]}


def test_image_normalization():
    assert fm.normalize_image("docker.io/library/php:8.3-fpm") == ("php", "8.3-fpm")
    assert fm.normalize_image("ghcr.io/berriai/litellm:v1.107.0") == ("berriai/litellm", "v1.107.0")
    assert fm.normalize_image("localhost:5000/app:1.0") == ("app", "1.0")
    assert fm.normalize_image("node@sha256:abc") == ("node", None)
    pk = fm.image_pkgs("gitlab/gitlab-ce:19.4.3-ce.0", "f", 1, "image:")
    assert pk[0].version == "19.4.3"


def test_requirements_parser():
    pk = fm.parse_requirements("Django==5.0.1\nfoo>=1\n# c\nbar[x]===2.0 ; python_version>'3'\n-e .\n", "r.txt")
    assert [(p.name, p.version) for p in pk] == [("Django", "5.0.1"), ("bar", "2.0")]


def test_toml_fallback_parser():
    text = '[[package]]\nname = "a"\nversion = "1.0"\n\n[package.dependencies]\nx = "1"\n\n[[package]]\nname = "b"\nversion = "2"\n'
    assert fm._toml_tables(text, "package") == [{"name": "a", "version": "1.0"}, {"name": "b", "version": "2"}]


def test_wp_plugin_requires_header(tmp_path):
    write(tmp_path, "wp-content/plugins/elementor/helper.php", "<?php\n// Version: 4.3.0 but not a plugin header\n")
    code, out, _ = run_script("feed_match.py", str(tmp_path))
    assert out["matches"] == []


def test_dockerfile_run_install_pins():
    text = (
        "FROM python:3.13-slim\n"
        "# pip install litellm==1.107.0 (comment, ignored)\n"
        "RUN pip install --no-cache-dir pip==26.2.1 && \\\n"
        "    pip install certifi==2026.10.19\n"
        "RUN npm i -g @modelcontextprotocol/sdk@1.31.0 left-pad@1.3.0\n"
        "COPY a==1 b\n"
    )
    pkgs = {(p.ecosystem, p.name, p.version, p.line) for p in fm.parse_dockerfile(text, "Dockerfile")}
    assert ("PyPI", "pip", "26.2.1", 3) in pkgs
    assert ("PyPI", "certifi", "2026.10.19", 4) in pkgs
    assert ("npm", "@modelcontextprotocol/sdk", "1.31.0", 5) in pkgs
    assert ("npm", "left-pad", "1.3.0", 5) in pkgs
    assert not any(p[1] == "litellm" for p in pkgs)
    assert not any(p[1] == "a" for p in pkgs)
