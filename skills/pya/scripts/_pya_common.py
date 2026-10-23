"""Shared helpers for the PYA scripts. Standard library only.

Safety rules every script follows:
- the target is data, never code: nothing in it is executed or imported;
- symlinks are never followed (files and directories), and every read is
  checked to resolve inside the target;
- noisy or generated directories are skipped;
- reads are size capped and binary files are ignored.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import os
import re
import stat
import sys

SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", ".venv", "venv", "dist", "build",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache", "bower_components",
    ".hg", ".svn", ".terraform", ".gradle", ".idea", "target",
})

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 200_000

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPT_DIR)
FEED_DIR = os.path.join(SKILL_DIR, "feed")
SEEDS_PATH = os.path.join(SKILL_DIR, "references", "seeds.json")


class UsageError(Exception):
    """Bad command line input. Scripts exit 2 on this."""


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def emit(obj) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=True))
    sys.stdout.write("\n")


def run_main(fn) -> None:
    """Run fn(argv) and map errors to exit codes (0 ok, 2 usage, 3 internal)."""
    try:
        code = fn(sys.argv[1:])
    except UsageError as exc:
        emit({"error": "usage", "message": str(exc)})
        sys.exit(2)
    except Exception as exc:  # internal error, report compactly
        emit({"error": "internal", "message": f"{type(exc).__name__}: {exc}"})
        sys.exit(3)
    sys.exit(code or 0)


def today() -> _dt.date:
    override = os.environ.get("PYA_TODAY")
    if override:
        return _dt.date.fromisoformat(override)
    return _dt.date.today()


# --------------------------------------------------------------------------
# Target handling
# --------------------------------------------------------------------------

def resolve_target(path: str) -> str:
    if not path:
        raise UsageError("missing <target> path")
    real = os.path.realpath(path)
    if not os.path.isdir(real):
        raise UsageError(f"target is not a directory: {path}")
    return real


def is_inside(root: str, path: str) -> bool:
    real = os.path.realpath(path)
    return real == root or real.startswith(root.rstrip(os.sep) + os.sep)


def walk(root: str, stats: dict | None = None, include_dirs: bool = False):
    """Yield (relpath, abspath, is_dir) for regular files under root.

    Symlinks are never followed. Symlinked entries are recorded in
    stats["symlinks"] with whether they escape the target. Entries that are
    not regular files (devices, FIFOs, sockets) go to stats["special_files"].
    """
    if stats is None:
        stats = {}
    stats.setdefault("symlinks", [])
    stats.setdefault("skipped_dirs", {})
    stats.setdefault("files_seen", 0)
    stats.setdefault("truncated", False)
    stats.setdefault("special_files", [])
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            abspath = entry.path
            rel = os.path.relpath(abspath, root).replace(os.sep, "/")
            try:
                if entry.is_symlink():
                    try:
                        dest = os.readlink(abspath)
                    except OSError:
                        dest = ""
                    stats["symlinks"].append({
                        "path": rel,
                        "target": dest[:300],
                        "escapes": not is_inside(root, abspath),
                    })
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIP_DIRS:
                        stats["skipped_dirs"][entry.name] = stats["skipped_dirs"].get(entry.name, 0) + 1
                        continue
                    if include_dirs:
                        yield rel, abspath, True
                    stack.append(abspath)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    stats["special_files"].append(rel)
                    continue
                # d_type can say "file" for a mount point; lstat sees what is really there.
                # Sandboxes mask dotfiles with /dev/null this way; devices and FIFOs are not source.
                if not stat.S_ISREG(os.lstat(abspath).st_mode):
                    stats["special_files"].append(rel)
                    continue
            except OSError:
                continue
            stats["files_seen"] += 1
            if stats["files_seen"] > MAX_FILES:
                stats["truncated"] = True
                return
            yield rel, abspath, False


def read_bytes(root: str, abspath: str, max_bytes: int = DEFAULT_MAX_BYTES):
    """Read a regular file without following symlinks. Returns bytes or None."""
    if not is_inside(root, abspath):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(abspath, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            return None
        return data
    except OSError:
        return None
    finally:
        os.close(fd)


def read_text(root: str, abspath: str, max_bytes: int = DEFAULT_MAX_BYTES):
    data = read_bytes(root, abspath, max_bytes)
    if data is None or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def file_size(abspath: str) -> int:
    try:
        return os.lstat(abspath).st_size
    except OSError:
        return -1


def line_index(text: str):
    """Return a function mapping a character offset to a 1-based line number."""
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    import bisect

    def lineno(offset: int) -> int:
        return bisect.bisect_right(starts, offset)

    return lineno


def glob_match(rel: str, pattern: str) -> bool:
    """Match a relative path against a glob. Patterns without '/' match the
    basename anywhere; patterns with '/' match the full relative path, where
    '**/' may match zero or more directories."""
    base = rel.rsplit("/", 1)[-1]
    if "/" not in pattern:
        return fnmatch.fnmatchcase(base, pattern)
    if fnmatch.fnmatchcase(rel, pattern):
        return True
    if pattern.startswith("**/"):
        sub = pattern[3:]
        parts = rel.split("/")
        for i in range(len(parts)):
            if fnmatch.fnmatchcase("/".join(parts[i:]), sub):
                return True
    return False


# --------------------------------------------------------------------------
# Feed loading
# --------------------------------------------------------------------------

FEED_NAME_RE = re.compile(r"^(\d{4})-(\d{2})\.json$")


def newest_feed(feed_dir: str = FEED_DIR):
    try:
        names = sorted(n for n in os.listdir(feed_dir) if FEED_NAME_RE.match(n))
    except OSError:
        return None
    return os.path.join(feed_dir, names[-1]) if names else None


def load_feed(path: str | None):
    if path is None:
        path = newest_feed()
    if path is None:
        return None, None
    with open(path, encoding="utf-8") as fh:
        return path, json.load(fh)


def feed_status(path: str, feed: dict) -> dict:
    as_of = _dt.date.fromisoformat(feed["as_of"])
    expires = _dt.date.fromisoformat(feed["expires"])
    now = today()
    age = (now - as_of).days
    return {
        "file": os.path.basename(path),
        "feed": feed.get("feed"),
        "as_of": feed["as_of"],
        "expires": feed["expires"],
        "age_days": age,
        "stale": age > 35,
        "expired": now > expires,
        "header": f"Threat feed: {feed.get('feed')} (as of {feed['as_of']}, {age} days old)",
    }


# --------------------------------------------------------------------------
# Version comparison (PEP 440-ish and semver-ish)
# --------------------------------------------------------------------------

_PRE_ALIASES = {
    "a": "a", "alpha": "a",
    "b": "b", "beta": "b",
    "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc",
}
_VERSION_HEAD = re.compile(r"^\s*[vV=]?\s*(?:(\d+)!)?(\d+(?:\.\d+)*)(.*)$")


def _ident(tok: str):
    """Comparable token: numbers sort before words (semver rule)."""
    if tok.isdigit():
        return (0, int(tok), "")
    return (1, 0, tok)


def version_key(raw: str):
    """Return a sortable key for a version string, or None if unparseable.

    Ordering: dev < pre-release (a < b < rc < other words) < final < post.
    Trailing zero segments are ignored, so 1.0 == 1.0.0. Build metadata
    after '+' is ignored.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    s = s.split("+", 1)[0]
    m = _VERSION_HEAD.match(s)
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    release = [int(x) for x in m.group(2).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = m.group(3).lower()
    # split the suffix into words and numbers
    tokens = [t for t in re.split(r"[.\-_]+|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)", rest) if t]
    phase = 2  # final
    detail: tuple = ()
    if tokens:
        first = tokens[0]
        if first in ("post", "rev", "r"):
            phase = 3
            detail = tuple(_ident(t) for t in tokens[1:])
        elif first == "dev":
            phase = 0
            detail = tuple(_ident(t) for t in tokens[1:])
        else:
            phase = 1
            norm = [_PRE_ALIASES.get(t, t) for t in tokens]
            # a trailing .devN on a pre-release sorts before the bare pre-release
            if "dev" in norm:
                idx = norm.index("dev")
                main = tuple(_ident(t) for t in norm[:idx])
                detail = (main, (0,) + tuple(_ident(t) for t in norm[idx + 1:]))
            else:
                detail = (tuple(_ident(t) for t in norm), (1,))
    return (epoch, tuple(release), phase, detail)


def compare(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        raise ValueError(f"cannot compare {a!r} and {b!r}")
    return (ka > kb) - (ka < kb)


def release_tuple(raw: str):
    m = _VERSION_HEAD.match(str(raw))
    if not m:
        return None
    return tuple(int(x) for x in m.group(2).split("."))


def in_range(version: str, rng: dict) -> bool:
    kv = version_key(version)
    if kv is None:
        return False
    intro = rng.get("introduced", "0")
    if intro not in ("0", "", None):
        ki = version_key(intro)
        if ki is None or kv < ki:
            return False
    if rng.get("fixed"):
        kf = version_key(rng["fixed"])
        return kf is not None and kv < kf
    if rng.get("last_affected"):
        kl = version_key(rng["last_affected"])
        return kl is not None and kv <= kl
    return True


def affected(version: str, entry: dict):
    """Return a 'why' string when the version is affected by the entry, else None."""
    kv = version_key(version)
    if kv is None:
        return None
    for exact in entry.get("versions", []) or []:
        if version_key(exact) == kv:
            return f"exact match {exact}"
    for rng in entry.get("ranges", []) or []:
        if in_range(version, rng):
            parts = [f">={rng.get('introduced', '0')}"]
            if rng.get("fixed"):
                parts.append(f"<{rng['fixed']}")
            elif rng.get("last_affected"):
                parts.append(f"<={rng['last_affected']}")
            return "in range " + ",".join(parts)
    return None


def branch_status(partial: str, entry: dict):
    """For a partial version like '20' or '8.3' (a floating tag), decide
    whether the whole branch is affected ('all'), only older builds in it
    ('some'), or none of it ('none')."""
    low = partial + ".0"
    high = partial + ".99999"
    lo = affected(low, entry)
    hi = affected(high, entry)
    if lo and hi:
        return "all", hi
    if lo or hi:
        return "some", lo or hi
    return "none", None


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[abpors]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
]
_ASSIGN_SECRET = re.compile(
    r"(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|auth(?:orization)?|"
    r"private[_-]?key|access[_-]?key|credential|_authToken)[\"']?\s*[:=]\s*[\"']?)"
    r"([^\s\"',;]{8,})"
)
_LONG_BLOB = re.compile(
    r"(?=[A-Za-z0-9+/_\-]*\d)(?=[A-Za-z0-9+/_\-]*[A-Za-z])[A-Za-z0-9+/_\-]{32,}={0,2}"
)
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def redact(line: str, limit: int = 200) -> str:
    text = line.strip()
    if "PRIVATE KEY" in text and "-----BEGIN" in text:
        return "-----BEGIN PRIVATE KEY----- [redacted]"
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: mask(m.group(0)), text)
    text = _ASSIGN_SECRET.sub(lambda m: m.group(1) + mask(m.group(2)), text)
    text = _LONG_BLOB.sub(lambda m: mask(m.group(0)), text)
    text = _INVISIBLE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text)
    if len(text) > limit:
        text = text[:limit] + "..."
    return text
