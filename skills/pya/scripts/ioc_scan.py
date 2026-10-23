#!/usr/bin/env python3
"""PYA IOC scan: technique seeds and feed indicators over the target's text files.

Usage: python3 -I ioc_scan.py <target> [--json] [--feed PATH] [--seeds PATH]
                                       [--max-per-id N] [--max-bytes N]
                                       [--include-self]

Runs every seed in references/seeds.json (Python re syntax) against files
matching its file_glob, and every IOC in the newest feed against all text
files (string and regex IOCs) or file paths (filename and path_glob IOCs).
Excerpts are redacted: secrets keep only their first and last 4 characters
and invisible Unicode is shown as <U+XXXX>. Hits are capped per id; totals
are still counted. Never executes anything from the target.
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

TEXT_MAX = 1024 * 1024


def load_seeds(path):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    seeds = doc["seeds"] if isinstance(doc, dict) else doc
    compiled = []
    for s in seeds:
        mode = s.get("match_on", "line")
        flags = re.M if mode in ("line", "file") else 0
        compiled.append((s, re.compile(s["regex"], flags), mode))
    return compiled


def compile_iocs(feed):
    text_iocs, path_iocs = [], []
    for e in (feed or {}).get("entries", []):
        for idx, ioc in enumerate(e.get("iocs", []) or []):
            meta = {
                "id": f"{e['id']}#{idx + 1}",
                "feed_id": e["id"],
                "title": e["title"],
                "severity": e["severity"],
                "malicious": e.get("malicious", False),
                "response_order": e.get("response_order"),
                "attack": e.get("attack"),
                "cwe": e.get("cwe"),
                "note": ioc.get("note"),
                "ioc_type": ioc["type"],
            }
            t, v = ioc["type"], ioc["value"]
            if t in ("string", "domain", "ip"):
                text_iocs.append((meta, re.compile(re.escape(v), re.M)))
            elif t == "regex":
                text_iocs.append((meta, re.compile(v, re.M)))
            elif t == "filename":
                path_iocs.append((meta, ("name", v)))
            elif t == "path_glob":
                path_iocs.append((meta, ("glob", v)))
    return text_iocs, path_iocs


class Collector:
    def __init__(self, cap):
        self.cap = cap
        self.hits = []
        self.counts = {}

    def add(self, key, hit):
        n = self.counts.get(key, 0) + 1
        self.counts[key] = n
        if n <= self.cap:
            self.hits.append(hit)


def seed_hit(seed, rel, line, excerpt):
    return {
        "source": "seed", "id": seed["id"], "agent": seed.get("agent"), "severity": seed.get("severity"),
        "title": seed["title"], "file": rel, "line": line, "excerpt": excerpt,
        "attack": seed.get("attack"), "cwe": seed.get("cwe"),
    }


def feed_hit(meta, rel, line, excerpt):
    return {
        "source": "feed", "id": meta["id"], "feed_id": meta["feed_id"], "severity": meta["severity"],
        "title": meta["title"], "file": rel, "line": line, "excerpt": excerpt, "note": meta["note"],
        "malicious": meta["malicious"], "response_order": meta["response_order"],
        "attack": meta["attack"], "cwe": meta["cwe"],
    }


def scan_text(rx, mode, text, lines, lineno):
    """Yield (line_number, excerpt_line) for each match."""
    if mode == "line":
        if not rx.search(text):  # fast reject on the whole file
            return
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                yield i, line
    else:
        for m in rx.finditer(text):
            pos = m.start("hit") if "hit" in rx.groupindex and m.group("hit") is not None else m.start()
            n = lineno(pos)
            yield n, lines[n - 1] if 0 < n <= len(lines) else ""


def self_prefix(target):
    """PYA's own skill directory (seeds, feed, references) is full of IOCs by
    design. When it sits inside the target, skip it unless asked not to."""
    skill = os.path.realpath(C.SKILL_DIR)
    if skill != target and C.is_inside(target, skill):
        return os.path.relpath(skill, target).replace(os.sep, "/") + "/"
    return None


def scan(target, seeds, text_iocs, path_iocs, cap, max_bytes, skip_prefix=None):
    stats: dict = {}
    col = Collector(cap)
    files_scanned = 0
    files_skipped = 0
    seed_checks = 0
    for rel, abspath, is_dir in C.walk(target, stats, include_dirs=True):
        if skip_prefix and (rel + "/").startswith(skip_prefix):
            continue
        name = rel.rsplit("/", 1)[-1]
        # path based seeds and IOCs (directories too, e.g. *.dist-info)
        for meta, (kind, value) in path_iocs:
            if (kind == "name" and name == value) or (kind == "glob" and C.glob_match(rel, value)):
                col.add(meta["id"], feed_hit(meta, rel, 0, rel))
        for seed, rx, mode in seeds:
            if mode == "path" and rx.search(rel):
                col.add(seed["id"], seed_hit(seed, rel, 0, rel))
        if is_dir:
            continue
        text = C.read_text(target, abspath, max_bytes)
        if text is None:
            if not os.access(abspath, os.R_OK):
                stats.setdefault("unreadable", []).append(rel)
            else:
                files_skipped += 1
            continue
        files_scanned += 1
        lines = text.splitlines()
        lineno = C.line_index(text)
        for seed, rx, mode in seeds:
            if mode == "path":
                continue
            if not any(C.glob_match(rel, g) for g in seed.get("file_glob") or ["*"]):
                continue
            seed_checks += 1
            for n, line in scan_text(rx, mode, text, lines, lineno):
                col.add(seed["id"], seed_hit(seed, rel, n, C.redact(line)))
        for meta, rx in text_iocs:
            for n, line in scan_text(rx, "line", text, lines, lineno):
                col.add(meta["id"], feed_hit(meta, rel, n, C.redact(line)))
    return col, files_scanned, files_skipped, seed_checks, stats


def main(argv) -> int:
    args = [a for a in argv if a != "--json"]
    include_self = "--include-self" in args
    args = [a for a in args if a != "--include-self"]
    opts = {"--feed": None, "--seeds": C.SEEDS_PATH, "--max-per-id": "20", "--max-bytes": str(TEXT_MAX)}
    for flag in list(opts):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                raise C.UsageError(f"{flag} needs a value")
            opts[flag] = args[i + 1]
            del args[i:i + 2]
    if len(args) != 1 or args[0].startswith("-"):
        raise C.UsageError("usage: ioc_scan.py <target> [--json] [--feed PATH] [--seeds PATH] [--max-per-id N]")
    try:
        cap = int(opts["--max-per-id"])
        max_bytes = int(opts["--max-bytes"])
    except ValueError:
        raise C.UsageError("--max-per-id and --max-bytes need integers")
    target = C.resolve_target(args[0])
    seeds = load_seeds(opts["--seeds"])
    feed_path, feed = C.load_feed(opts["--feed"])
    text_iocs, path_iocs = compile_iocs(feed)
    skip_prefix = None if include_self else self_prefix(target)
    col, scanned, skipped, checks, stats = scan(target, seeds, text_iocs, path_iocs, cap, max_bytes, skip_prefix)
    truncated = {k: v for k, v in col.counts.items() if v > cap}
    C.emit({
        "tool": "ioc_scan",
        "target": target,
        "feed": C.feed_status(feed_path, feed) if feed else None,
        "inspected": {
            "seeds": len(seeds),
            "feed_iocs": len(text_iocs) + len(path_iocs),
            "files_scanned": scanned,
            "files_skipped_binary_or_large": skipped,
            # Unreadable files are unreviewed, not clean. A sandbox can mask dotfiles this way.
            "files_unreadable": len(stats.get("unreadable", [])),
            "unreadable_sample": stats.get("unreadable", [])[:20],
            "seed_file_checks": checks,
        },
        "hits": col.hits,
        "counts": col.counts,
        "truncated": truncated,
        "max_per_id": cap,
        "symlinks_skipped": len(stats.get("symlinks", [])),
        "special_files_skipped": len(stats.get("special_files", [])),
        "self_excluded": skip_prefix,
        "note": "Hits are leads for the agents to verify, not findings. No hit is not proof of absence.",
    })
    return 0


if __name__ == "__main__":
    C.run_main(main)
