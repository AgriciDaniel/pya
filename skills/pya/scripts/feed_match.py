#!/usr/bin/env python3
"""PYA feed matcher: pinned versions in the target against the dated threat feed.

Usage: python3 -I feed_match.py <target> [--json] [--feed PATH] [--kev PATH]

Parses lockfiles, manifests, WordPress headers, container image tags and
runtime pins as text (nothing in the target is executed or imported), then
reports every package, image or runtime version the newest feed marks as
affected. If a CISA KEV snapshot exists (see update_kev.py) any matched CVE
alias found in it is flagged kev. Output is compact JSON on stdout.
"""

from __future__ import annotations

import json
import os
import re
import sys

try:  # Python 3.11+
    import tomllib
    TOMLError = tomllib.TOMLDecodeError
except ImportError:  # Python 3.10: fall back to a line parser
    tomllib = None
    TOMLError = ValueError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

LOCK_MAX = 50 * 1024 * 1024
TEXT_MAX = 2 * 1024 * 1024


class Pkg:
    __slots__ = ("ecosystem", "name", "version", "file", "line", "source", "partial", "confidence", "spec")

    def __init__(self, ecosystem, name, version, file, line, source, partial=False, confidence="high", spec=None):
        self.ecosystem = ecosystem
        self.name = name
        self.version = version
        self.file = file
        self.line = line
        self.source = source
        self.partial = partial
        self.confidence = confidence
        self.spec = spec


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return pep503(name)
    if ecosystem in ("WordPress", "Docker", "runtime", "Packagist"):
        return name.lower()
    return name


def find_line(text: str, needle: str, lineno, start: int = 0) -> int:
    pos = text.find(needle, start)
    return lineno(pos) if pos >= 0 else 0


# --------------------------------------------------------------------------
# npm family
# --------------------------------------------------------------------------

def parse_package_lock(text, rel):
    data = json.loads(text)
    out = []
    lineno = C.line_index(text)
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue
            version = meta.get("version")
            if not version:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.append(Pkg("npm", name, version, rel, find_line(text, f'"{path}"', lineno), "package-lock"))
        return out

    def walk_v1(deps):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version and not str(version).startswith(("file:", "link:", "git")):
                if str(version).startswith("npm:"):
                    real = version[4:]
                    at = real.rfind("@")
                    if at > 0:
                        name, version = real[:at], real[at + 1:]
                out.append(Pkg("npm", name, version, rel, find_line(text, f'"{name}"', lineno), "package-lock-v1"))
            walk_v1(meta.get("dependencies"))

    walk_v1(data.get("dependencies"))
    return out


def split_name_version(spec: str):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3')."""
    at = spec.rfind("@")
    if at <= 0:
        return None, None
    return spec[:at], spec[at + 1:]


def parse_pnpm_lock(text, rel):
    out = []
    seen = set()
    section = None
    for i, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith(" "):
            section = line.rstrip(":").strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        m = re.match(r"^  (['\"]?)(/?[^\s'\"]+?)\1:\s*$", line)
        if not m:
            continue
        key = m.group(2).lstrip("/")
        key = re.sub(r"\(.*\)$", "", key)
        if "@" in key[1:]:
            name, version = split_name_version(key)
        else:  # lockfile v5: name/1.2.3[_peer]
            name, _, version = key.rpartition("/")
        if not name or not version:
            continue
        version = version.split("_", 1)[0]
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append(Pkg("npm", name, version, rel, i, "pnpm-lock"))
    return out


def parse_yarn_lock(text, rel):
    out = []
    header = None
    header_line = 0
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            raw = line.rstrip()[:-1].strip()
            if raw == "__metadata":
                header = None
                continue
            first = raw.split(",")[0].strip().strip('"')
            name, _ = split_name_version(first)
            header, header_line = name, i
            continue
        if header:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
            if m:
                version = m.group(1)
                if not version.startswith("0.0.0-use.local"):
                    out.append(Pkg("npm", header, version, rel, header_line, "yarn-lock"))
                header = None
    return out


def strip_jsonc(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def parse_bun_lock(text, rel):
    data = json.loads(strip_jsonc(text))
    out = []
    lineno = C.line_index(text)
    for _key, value in (data.get("packages") or {}).items():
        if isinstance(value, list) and value and isinstance(value[0], str):
            name, version = split_name_version(value[0])
            if name and version and not version.startswith(("workspace:", "file:", "link:", "git")):
                if version.startswith("npm:"):
                    version = version[4:]
                out.append(Pkg("npm", name, version, rel, find_line(text, f'"{value[0]}"', lineno), "bun-lock"))
    return out


def range_floor(spec: str):
    """Lower bound of a simple npm or pip range, and whether it is an exact pin."""
    s = str(spec).strip()
    if not s or any(s.startswith(p) for p in ("file:", "link:", "git", "http", "workspace:", "npm:", "*", "latest")):
        return None, False
    s = s.split("||")[0].strip()
    m = re.match(r"^(=|==|===)?\s*v?(\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?)$", s)
    if m:
        return m.group(2), True
    m = re.match(r"^(?:\^|~|~=|>=|>)?\s*v?(\d+(?:\.(?:\d+|x|\*))*)", s)
    if m:
        ver = re.sub(r"\.(?:x|\*)", "", m.group(1))
        return ver, False
    return None, False


def runtime_spec_is_pin(spec: str) -> bool:
    """engines / composer "php" are compatibility ranges. Only treat them as a
    statement about the runtime in use when they pin one line: an exact
    version, "20", "20.x" or "8.3.*". Open ranges (>=, ^, ~, ||) are skipped."""
    s = spec.strip()
    return bool(s) and not s.startswith((">", "^", "~", "<")) and "||" not in s and " " not in s


def parse_package_json(text, rel):
    data = json.loads(text)
    out = []
    lineno = C.line_index(text)
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            floor, exact = range_floor(spec)
            if floor:
                out.append(Pkg("npm", name, floor, rel, find_line(text, f'"{name}"', lineno), "package.json",
                               partial=not exact and floor.count(".") < 2,
                               confidence="medium" if exact else "low", spec=spec))
    engines = data.get("engines") if isinstance(data.get("engines"), dict) else {}
    for key, runtime in (("node", "node"), ("bun", "bun")):
        spec = engines.get(key)
        if isinstance(spec, str) and runtime_spec_is_pin(spec):
            floor, exact = range_floor(spec)
            if floor:
                out.append(Pkg("runtime", runtime, floor, rel, find_line(text, f'"{key}"', lineno), "engines",
                               partial=not exact and floor.count(".") < 2, confidence="low", spec=spec))
    pm = data.get("packageManager")
    if isinstance(pm, str) and pm.startswith("bun@"):
        out.append(Pkg("runtime", "bun", pm[4:].split("+")[0], rel, find_line(text, '"packageManager"', lineno),
                       "packageManager"))
    return out


# --------------------------------------------------------------------------
# Python family
# --------------------------------------------------------------------------

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(===?)\s*([^\s;#,\\]+)")


def parse_requirements(text, rel):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", "-")):
            continue
        m = REQ_RE.match(line)
        if m and "*" not in m.group(3):
            out.append(Pkg("PyPI", m.group(1), m.group(3), rel, i, "requirements"))
    return out


def _toml_tables(text, key):
    """Minimal [[key]] reader for Python 3.10 (name and version only)."""
    tables, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            cur = {} if s == f"[[{key}]]" else None
            if cur is not None:
                tables.append(cur)
            continue
        if cur is not None:
            m = re.match(r'^(name|version)\s*=\s*"([^"]*)"', s)
            if m:
                cur[m.group(1)] = m.group(2)
    return tables


def toml_packages(text, rel, key, source):
    tables = tomllib.loads(text).get(key, []) if tomllib else _toml_tables(text, key)
    out = []
    lineno = C.line_index(text)
    for pkg in tables or []:
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            out.append(Pkg("PyPI", name, str(version), rel, find_line(text, f'name = "{name}"', lineno), source))
    return out


def parse_pipfile_lock(text, rel):
    data = json.loads(text)
    out = []
    lineno = C.line_index(text)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                out.append(Pkg("PyPI", name, meta["version"].lstrip("="), rel,
                               find_line(text, f'"{name}"', lineno), "Pipfile.lock"))
    return out


# --------------------------------------------------------------------------
# PHP and WordPress
# --------------------------------------------------------------------------

def composer_target(name: str):
    lname = name.lower()
    if lname.startswith(("wpackagist-plugin/", "wpackagist-theme/")):
        return "WordPress", lname.split("/", 1)[1]
    if lname in ("johnpbloch/wordpress-core", "johnpbloch/wordpress", "roots/wordpress", "roots/wordpress-no-content"):
        return "WordPress", "wordpress"
    return "Packagist", lname


def parse_composer_lock(text, rel):
    data = json.loads(text)
    out = []
    lineno = C.line_index(text)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name, version = pkg.get("name"), pkg.get("version")
            if name and isinstance(version, str) and not version.startswith("dev-"):
                eco, pname = composer_target(name)
                out.append(Pkg(eco, pname, version.lstrip("v"), rel,
                               find_line(text, f'"name": "{name}"', lineno), "composer.lock"))
    return out


def parse_composer_json(text, rel):
    data = json.loads(text)
    out = []
    lineno = C.line_index(text)
    req = data.get("require") if isinstance(data.get("require"), dict) else {}
    spec = req.get("php")
    if isinstance(spec, str) and runtime_spec_is_pin(spec):
        floor, exact = range_floor(spec)
        if floor:
            out.append(Pkg("runtime", "php", floor, rel, find_line(text, '"php"', lineno), "composer.json",
                           partial=not exact and floor.count(".") < 2, confidence="low", spec=spec))
    return out


WP_VERSION_RE = re.compile(r"^\s*\*?\s*Version:\s*([0-9][0-9A-Za-z.\-]*)", re.M | re.I)
WP_NAME_RE = re.compile(r"^\s*\*?\s*Plugin Name:", re.M | re.I)
WP_STABLE_RE = re.compile(r"^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", re.M | re.I)
WP_CORE_RE = re.compile(r"^\s*\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", re.M)


def parse_wp_plugin(text, rel, slug, kind):
    lineno = C.line_index(text)
    if kind == "php":
        head = text[:8192]
        if not WP_NAME_RE.search(head):
            return []
        m = WP_VERSION_RE.search(head)
        regex_used = m
    else:
        m = WP_STABLE_RE.search(text[:16384])
        regex_used = m
    if not regex_used:
        return []
    return [Pkg("WordPress", slug.lower(), m.group(1), rel, lineno(m.start(1)),
                "plugin-header" if kind == "php" else "readme-stable-tag",
                confidence="high" if kind == "php" else "medium")]


def parse_wp_core(text, rel):
    m = WP_CORE_RE.search(text)
    if not m:
        return []
    return [Pkg("WordPress", "wordpress", m.group(1), rel, C.line_index(text)(m.start(1)), "wp-version.php")]


# --------------------------------------------------------------------------
# Containers and runtime pins
# --------------------------------------------------------------------------

IMAGE_RUNTIME = {"node": "node", "php": "php", "docker": "docker", "oven/bun": "bun",
                 "podman/stable": "podman", "containers/podman": "podman"}
TAG_VER_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")


def normalize_image(ref: str):
    ref = ref.strip().strip("'\"")
    ref = ref.split("@", 1)[0]
    if not ref or "$" in ref:
        return None, None
    last = ref.rsplit("/", 1)[-1]
    tag = None
    if ":" in last:
        repo_last, tag = last.split(":", 1)
        ref = ref[: len(ref) - len(last)] + repo_last
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    if parts and parts[0] == "library":
        parts = parts[1:]
    return "/".join(parts).lower(), tag


def image_pkgs(ref: str, rel: str, line: int, source: str):
    name, tag = normalize_image(ref)
    if not name or not tag:
        return []
    m = TAG_VER_RE.match(tag)
    if not m:
        return []
    version = m.group(1)
    partial = version.count(".") < 2
    out = [Pkg("Docker", name, version, rel, line, source, partial=partial, spec=f"{name}:{tag}")]
    if name in IMAGE_RUNTIME:
        out.append(Pkg("runtime", IMAGE_RUNTIME[name], version, rel, line, source, partial=partial,
                       spec=f"{name}:{tag}"))
    return out


FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I)
ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", re.I)
IMAGE_RE = re.compile(r"^\s*-?\s*image:\s*['\"]?([^\s'\"#]+)")
PIP_PIN_RE = re.compile(r"(?<![\w.\-])([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?==([0-9][^\s\"'\\;&|,]*)")
NPM_PIN_RE = re.compile(r"(?<![\w.\-/@])((?:@[\w.\-]+/)?[\w.\-]+)@([0-9][^\s\"'\\;&|,]*)")


def parse_install_pins(line, rel, i, source):
    """Exact pins installed by a RUN line, e.g. `pip install pip==26.2.1` or `npm i -g x@1.2.3`."""
    out = []
    low = line.lower()
    if "pip" in low and "install" in low:
        out.extend(Pkg("PyPI", m.group(1), m.group(2), rel, i, source) for m in PIP_PIN_RE.finditer(line))
    if re.search(r"\b(?:npm|pnpm|yarn|bun)\b", low) and re.search(r"\b(?:install|i|add)\b", low):
        out.extend(Pkg("npm", m.group(1), m.group(2), rel, i, source) for m in NPM_PIN_RE.finditer(line))
    return out


def parse_dockerfile(text, rel):
    out = []
    args = {}
    for i, line in enumerate(text.splitlines(), 1):
        if not line.lstrip().startswith("#"):
            out.extend(parse_install_pins(line, rel, i, "Dockerfile RUN"))
        m = ARG_RE.match(line)
        if m:
            args[m.group(1)] = m.group(2).strip("'\"")
            continue
        m = FROM_RE.match(line)
        if m:
            ref = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}?",
                         lambda mm: args.get(mm.group(1), mm.group(2) or "$"), m.group(1))
            out.extend(image_pkgs(ref, rel, i, "Dockerfile"))
    return out


def parse_yaml_images(text, rel):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = IMAGE_RE.match(line)
        if m:
            out.extend(image_pkgs(m.group(1), rel, i, "image:"))
    return out


def parse_runtime_pin(text, rel, runtime):
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^v?(\d+(?:\.\d+)*)", s)
        if not m:
            return []
        v = m.group(1)
        return [Pkg("runtime", runtime, v, rel, i, os.path.basename(rel), partial=v.count(".") < 2)]
    return []


TOOL_VERSIONS = {"nodejs": "node", "node": "node", "php": "php", "bun": "bun"}


def parse_tool_versions(text, rel):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] in TOOL_VERSIONS:
            m = re.match(r"^v?(\d+(?:\.\d+)*)", parts[1])
            if m:
                v = m.group(1)
                out.append(Pkg("runtime", TOOL_VERSIONS[parts[0]], v, rel, i, ".tool-versions",
                               partial=v.count(".") < 2))
    return out


def parse_go_mod(text, rel):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]+/[^\s]+)\s+(v[0-9][^\s]*)", line)
        if m:
            out.append(Pkg("Go", m.group(1), m.group(2).lstrip("v"), rel, i, "go.mod"))
    return out


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

def parser_for(rel: str):
    name = rel.rsplit("/", 1)[-1]
    lname = name.lower()
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return parse_package_lock, LOCK_MAX
    if name == "pnpm-lock.yaml":
        return parse_pnpm_lock, LOCK_MAX
    if name == "yarn.lock":
        return parse_yarn_lock, LOCK_MAX
    if name == "bun.lock":
        return parse_bun_lock, LOCK_MAX
    if name == "package.json":
        return parse_package_json, TEXT_MAX
    if re.match(r"^requirements.*\.txt$", lname) or (rel.startswith("requirements/") and lname.endswith(".txt")):
        return parse_requirements, TEXT_MAX
    if name == "poetry.lock":
        return (lambda t, r: toml_packages(t, r, "package", "poetry.lock")), LOCK_MAX
    if name == "uv.lock":
        return (lambda t, r: toml_packages(t, r, "package", "uv.lock")), LOCK_MAX
    if name == "pylock.toml" or re.match(r"^pylock\.[^/]+\.toml$", name):
        return (lambda t, r: toml_packages(t, r, "packages", "pylock")), LOCK_MAX
    if name == "Pipfile.lock":
        return parse_pipfile_lock, LOCK_MAX
    if name == "composer.lock":
        return parse_composer_lock, LOCK_MAX
    if name == "composer.json":
        return parse_composer_json, TEXT_MAX
    if rel.endswith("wp-includes/version.php"):
        return parse_wp_core, TEXT_MAX
    m = re.search(r"(?:^|/)(?:wp-content/)?plugins/([^/]+)/([^/]+)$", rel)
    if m and lname.endswith(".php"):
        slug = m.group(1)
        return (lambda t, r: parse_wp_plugin(t, r, slug, "php")), 512 * 1024
    if m and lname == "readme.txt":
        slug = m.group(1)
        return (lambda t, r: parse_wp_plugin(t, r, slug, "readme")), 512 * 1024
    if lname.startswith(("dockerfile", "containerfile")) or lname.endswith((".dockerfile", ".containerfile")):
        return parse_dockerfile, TEXT_MAX
    if lname.endswith((".yml", ".yaml")) and name != "pnpm-lock.yaml":
        return parse_yaml_images, TEXT_MAX
    if name in (".nvmrc", ".node-version"):
        return (lambda t, r: parse_runtime_pin(t, r, "node")), 4096
    if name == ".php-version":
        return (lambda t, r: parse_runtime_pin(t, r, "php")), 4096
    if name == ".bun-version":
        return (lambda t, r: parse_runtime_pin(t, r, "bun")), 4096
    if name == ".tool-versions":
        return parse_tool_versions, 65536
    if name == "go.mod":
        return parse_go_mod, TEXT_MAX
    return None, 0


def load_kev(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    cves = data.get("cves")
    if cves is None and isinstance(data.get("vulnerabilities"), list):
        cves = {v.get("cveID"): v for v in data["vulnerabilities"] if v.get("cveID")}
    return {
        "catalogVersion": data.get("catalogVersion"),
        "dateReleased": data.get("dateReleased"),
        "cves": cves or {},
    }


def default_kev_path():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "pya", "kev.json")


def match(pkgs, entries, kev):
    index = {}
    for e in entries:
        if e.get("kind") == "technique" or not e.get("package") or not e.get("ecosystem"):
            continue
        if not e.get("ranges") and not e.get("versions"):
            continue
        index.setdefault((e["ecosystem"], norm_name(e["ecosystem"], e["package"])), []).append(e)
    # package.json declared ranges are skipped when a lockfile in the same dir resolved the package
    locked = {(os.path.dirname(p.file), p.name) for p in pkgs if p.source not in ("package.json", "engines")}
    results = []
    seen = set()
    for p in pkgs:
        if p.source == "package.json" and (os.path.dirname(p.file), p.name) in locked:
            continue
        for e in index.get((p.ecosystem, norm_name(p.ecosystem, p.name)), []):
            confidence = p.confidence
            if p.partial:
                status, why = C.branch_status(p.version, e)
                if status == "none":
                    continue
                if status == "some":
                    why = (f"floating {p.version} line includes affected builds ({why}); "
                           f"pull and rebuild to reach {', '.join(e.get('fixed_in', [])) or 'a fixed release'}")
                    confidence = "low"
                else:
                    why = f"whole {p.version} line affected ({why})"
            else:
                why = C.affected(p.version, e)
                if not why:
                    continue
            if p.spec and p.source in ("package.json", "engines", "composer.json"):
                why = f"declared {p.spec!r}, lower bound {p.version}: {why}; confirm with a lockfile"
            key = (e["id"], p.file, p.line, p.name, p.version)
            if key in seen:
                continue
            seen.add(key)
            kev_flag = bool(e.get("kev"))
            kev_hits = []
            if kev:
                kev_hits = [a for a in e.get("aliases", []) if a in kev["cves"]]
                kev_flag = kev_flag or bool(kev_hits)
            results.append({
                "feed_id": e["id"],
                "title": e["title"],
                "ecosystem": p.ecosystem,
                "package": p.name,
                "found_version": p.spec or p.version,
                "file": p.file,
                "line": p.line,
                "source": p.source,
                "why": why,
                "match_confidence": confidence,
                "severity": e["severity"],
                "kev": kev_flag,
                "kev_cache_hits": kev_hits,
                "malicious": e.get("malicious", False),
                "feed_confidence": e.get("confidence"),
                "response_order": e.get("response_order"),
                "fixed_in": e.get("fixed_in", []),
                "aliases": e.get("aliases", []),
                "advice": e.get("advice"),
                "digest_ref": e.get("digest_ref"),
                "sources": e.get("sources", []),
            })
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    results.sort(key=lambda r: (not r["kev"], not r["malicious"], sev_rank.get(r["severity"], 9), r["file"], r["line"]))
    return results


def collect(target):
    stats: dict = {}
    pkgs = []
    inputs = []
    errors = []
    for rel, abspath, _ in C.walk(target, stats):
        parser, limit = parser_for(rel)
        if not parser:
            continue
        text = C.read_text(target, abspath, limit)
        if text is None:
            if C.file_size(abspath) > limit:
                errors.append({"file": rel, "error": f"skipped, larger than {limit} bytes"})
            continue
        try:
            found = parser(text, rel)
        except (ValueError, KeyError, TypeError, AttributeError, TOMLError) as exc:
            errors.append({"file": rel, "error": f"parse failed: {type(exc).__name__}"})
            continue
        if found or not rel.lower().endswith((".yml", ".yaml", ".php", "readme.txt")):
            inputs.append({"file": rel, "parser": parser.__name__ if hasattr(parser, "__name__") else "parser",
                           "items": len(found)})
        pkgs.extend(found)
    return pkgs, inputs, errors, stats


def main(argv) -> int:
    args = [a for a in argv if a != "--json"]
    feed_path = None
    kev_path = default_kev_path()
    for flag in ("--feed", "--kev"):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                raise C.UsageError(f"{flag} needs a path")
            if flag == "--feed":
                feed_path = args[i + 1]
            else:
                kev_path = args[i + 1]
            del args[i:i + 2]
    if len(args) != 1 or args[0].startswith("-"):
        raise C.UsageError("usage: feed_match.py <target> [--json] [--feed PATH] [--kev PATH]")
    target = C.resolve_target(args[0])
    path, feed = C.load_feed(feed_path)
    if feed is None:
        raise C.UsageError("no feed file found (pass --feed PATH)")
    kev = load_kev(kev_path)
    pkgs, inputs, errors, stats = collect(target)
    matches = match(pkgs, feed.get("entries", []), kev)
    counts = {}
    for m in matches:
        counts[m["severity"]] = counts.get(m["severity"], 0) + 1
    C.emit({
        "tool": "feed_match",
        "target": target,
        "feed": C.feed_status(path, feed),
        "kev_cache": ({"present": True, "catalogVersion": kev["catalogVersion"],
                       "dateReleased": kev["dateReleased"], "cves": len(kev["cves"])}
                      if kev else {"present": False, "hint": "run update_kev.py (network, opt-in) to add CISA KEV"}),
        "inspected": {"files": len(inputs), "packages": len(pkgs), "feed_entries": len(feed.get("entries", []))},
        "inputs": inputs[:500],
        "errors": errors[:200],
        "matches": matches,
        "counts": counts,
        "kev_matches": sum(1 for m in matches if m["kev"]),
        "malicious_matches": sum(1 for m in matches if m["malicious"]),
        "symlinks_skipped": len(stats.get("symlinks", [])),
        "note": "No match means no feed entry matched in parsed files, not proof of absence.",
    })
    return 0


if __name__ == "__main__":
    C.run_main(main)
