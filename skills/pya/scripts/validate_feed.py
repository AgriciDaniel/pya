#!/usr/bin/env python3
"""Validate PYA feed files against the essentials of feed/schema.json.

Usage: python3 -I validate_feed.py <feed.json> [<feed.json> ...] [--json]

Standard library only. Checks required fields, unknown fields, the id
pattern and its month prefix, unique ids, enums, ISO dates, expires after
as_of, https sources, IOC regexes that compile, response_order keys, no
live links or em/en dashes in text, and that ranges or versions exist for
package-like entries. Prints compact JSON. Exit 0 when every file is
valid, 1 when any file has errors, 2 on usage error.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

TOP_REQUIRED = ["feed", "as_of", "expires", "source_digest", "entries"]
TOP_ALLOWED = set(TOP_REQUIRED)
ENTRY_REQUIRED = ["id", "title", "kind", "severity", "kev", "malicious", "confidence", "sources", "digest_ref"]
ENTRY_ALLOWED = set(ENTRY_REQUIRED) | {
    "ecosystem", "package", "aliases", "ranges", "versions", "fixed_in", "cwe", "attack", "iocs",
    "response_order", "advice",
}
KINDS = {"package", "runtime", "image", "plugin", "tool", "technique"}
ECOSYSTEMS = {"npm", "PyPI", "Packagist", "WordPress", "Docker", "Go", "crates.io", "RubyGems", "Maven",
              "NuGet", "runtime"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CONFIDENCES = {"confirmed", "secondary", "unverified"}
IOC_TYPES = {"filename", "path_glob", "string", "regex", "domain", "ip"}
RANGE_KEYS = {"introduced", "fixed", "last_affected"}
FALLBACK_RESPONSE_KEYS = {"tensorlake-wiper", "litellm-pth", "updraft-backdoor", "wp-sc-backdoor",
                          "php-fpm-restart", "rebuild-images", "rotate-on-exposure", "emsign-trust"}
SECTION = chr(0xA7)
ID_RE = re.compile(r"^PYA-[0-9]{4}-[0-9]{2}-[0-9]{3}$")
FEED_RE = re.compile(r"^[0-9]{4}-[0-9]{2}$")
DIGEST_REF_RE = re.compile("^D" + SECTION + "[0-9]+$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
ATTACK_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
DASHES = (chr(0x2014), chr(0x2013))


def response_keys():
    path = os.path.join(C.SKILL_DIR, "references", "response-order.md")
    try:
        with open(path, encoding="utf-8") as fh:
            keys = set(re.findall(r"^\|\s*`([a-z0-9\-]+)`\s*\|", fh.read(), re.M))
        return keys or FALLBACK_RESPONSE_KEYS
    except OSError:
        return FALLBACK_RESPONSE_KEYS


def parse_date(value, field, errors):
    if not isinstance(value, str):
        errors.append(f"{field}: must be a YYYY-MM-DD string")
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        errors.append(f"{field}: not a valid date: {value!r}")
        return None


def walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v)


def check_entry(e, i, month, keys, errors):
    where = f"entries[{i}]"
    if not isinstance(e, dict):
        errors.append(f"{where}: must be an object")
        return None
    eid = e.get("id", "?")
    where = f"entries[{i}] {eid}"
    for k in ENTRY_REQUIRED:
        if k not in e:
            errors.append(f"{where}: missing required field {k!r}")
    for k in e:
        if k not in ENTRY_ALLOWED:
            errors.append(f"{where}: unknown field {k!r}")
    if not isinstance(eid, str) or not ID_RE.match(eid):
        errors.append(f"{where}: id must match PYA-YYYY-MM-NNN")
    elif month and not eid.startswith(f"PYA-{month}-"):
        errors.append(f"{where}: id month does not match feed {month}")
    if not isinstance(e.get("title"), str) or not e.get("title", "").strip():
        errors.append(f"{where}: title must be a non-empty string")
    if e.get("kind") not in KINDS:
        errors.append(f"{where}: kind must be one of {sorted(KINDS)}")
    if "ecosystem" in e and e["ecosystem"] not in ECOSYSTEMS:
        errors.append(f"{where}: ecosystem {e['ecosystem']!r} not allowed")
    if e.get("severity") not in SEVERITIES:
        errors.append(f"{where}: severity must be one of {sorted(SEVERITIES)}")
    if e.get("confidence") not in CONFIDENCES:
        errors.append(f"{where}: confidence must be one of {sorted(CONFIDENCES)}")
    for flag in ("kev", "malicious"):
        if flag in e and not isinstance(e[flag], bool):
            errors.append(f"{where}: {flag} must be true or false")
    if not isinstance(e.get("digest_ref"), str) or not DIGEST_REF_RE.match(e.get("digest_ref", "")):
        errors.append(f"{where}: digest_ref must look like D{SECTION}11")
    sources = e.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append(f"{where}: sources must be a non-empty list")
    else:
        for s in sources:
            if not isinstance(s, str) or not s.startswith("https://") or " " in s:
                errors.append(f"{where}: source is not an https URL: {s!r}")
        if len(set(sources)) != len(sources):
            errors.append(f"{where}: duplicate source URL")
    for field in ("aliases", "versions", "fixed_in"):
        if field in e and (not isinstance(e[field], list) or not all(isinstance(x, str) and x for x in e[field])):
            errors.append(f"{where}: {field} must be a list of non-empty strings")
    for r_i, rng in enumerate(e.get("ranges", []) or []):
        if not isinstance(rng, dict) or "introduced" not in rng:
            errors.append(f"{where}: ranges[{r_i}] needs 'introduced'")
            continue
        extra = set(rng) - RANGE_KEYS
        if extra:
            errors.append(f"{where}: ranges[{r_i}] unknown keys {sorted(extra)}")
        if "fixed" in rng and "last_affected" in rng:
            errors.append(f"{where}: ranges[{r_i}] has both fixed and last_affected")
        for k, v in rng.items():
            if k in RANGE_KEYS and (not isinstance(v, str) or (v != "0" and C.version_key(v) is None)):
                errors.append(f"{where}: ranges[{r_i}].{k} is not a version: {v!r}")
        if rng.get("introduced") not in (None, "0") and rng.get("fixed"):
            try:
                if C.compare(rng["introduced"], rng["fixed"]) >= 0:
                    errors.append(f"{where}: ranges[{r_i}] introduced is not below fixed")
            except ValueError:
                pass
    if e.get("kind") != "technique":
        if not e.get("ecosystem") or not e.get("package"):
            errors.append(f"{where}: non-technique entries need ecosystem and package")
        if not e.get("ranges") and not e.get("versions"):
            errors.append(f"{where}: non-technique entries need ranges or versions")
    elif not e.get("iocs"):
        errors.append(f"{where}: technique entries need iocs")
    for j, ioc in enumerate(e.get("iocs", []) or []):
        if not isinstance(ioc, dict):
            errors.append(f"{where}: iocs[{j}] must be an object")
            continue
        for k in ("type", "value", "note"):
            if not isinstance(ioc.get(k), str) or not ioc.get(k):
                errors.append(f"{where}: iocs[{j}] needs a non-empty {k!r}")
        extra = set(ioc) - {"type", "value", "note"}
        if extra:
            errors.append(f"{where}: iocs[{j}] unknown keys {sorted(extra)}")
        if ioc.get("type") not in IOC_TYPES:
            errors.append(f"{where}: iocs[{j}] type must be one of {sorted(IOC_TYPES)}")
        if ioc.get("type") == "regex":
            try:
                re.compile(ioc.get("value", ""))
            except re.error as exc:
                errors.append(f"{where}: iocs[{j}] regex does not compile: {exc}")
        if ioc.get("type") in ("domain", "ip"):
            errors.append(f"{where}: iocs[{j}] use type 'regex' with escaped dots so no live link is stored")
        if "://" in ioc.get("value", "") and ioc.get("type") != "regex":
            errors.append(f"{where}: iocs[{j}] value contains a URL scheme")
        if "://" in ioc.get("note", ""):
            errors.append(f"{where}: iocs[{j}] note must not contain a link; defang it")
    ro = e.get("response_order")
    if ro is not None and ro not in keys:
        errors.append(f"{where}: response_order {ro!r} is not a key in references/response-order.md")
    if "cwe" in e and not CWE_RE.match(str(e["cwe"])):
        errors.append(f"{where}: cwe must look like CWE-79")
    if "attack" in e and not ATTACK_RE.match(str(e["attack"])):
        errors.append(f"{where}: attack must look like T1546 or T1546.018")
    for field in ("title", "advice"):
        if "://" in str(e.get(field, "")):
            errors.append(f"{where}: {field} must not contain a link")
    for s in walk_strings(e):
        if any(d in s for d in DASHES):
            errors.append(f"{where}: em or en dash in text")
            break
    return eid


def validate(path):
    errors = []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        return {"file": path, "ok": False, "entries": 0, "errors": [f"cannot read JSON: {exc}"]}
    if not isinstance(doc, dict):
        return {"file": path, "ok": False, "entries": 0, "errors": ["top level must be an object"]}
    for k in TOP_REQUIRED:
        if k not in doc:
            errors.append(f"missing required field {k!r}")
    for k in doc:
        if k not in TOP_ALLOWED:
            errors.append(f"unknown top-level field {k!r}")
    month = doc.get("feed") if isinstance(doc.get("feed"), str) and FEED_RE.match(doc.get("feed", "")) else None
    if not month:
        errors.append("feed must look like YYYY-MM")
    base = os.path.basename(path)
    if month and re.match(r"^\d{4}-\d{2}\.json$", base) and base != f"{month}.json":
        errors.append(f"file name {base} does not match feed {month}")
    as_of = parse_date(doc.get("as_of"), "as_of", errors)
    expires = parse_date(doc.get("expires"), "expires", errors)
    if as_of and expires and expires <= as_of:
        errors.append("expires must be after as_of")
    if as_of and month and as_of.strftime("%Y-%m") != month:
        errors.append("as_of is not in the feed month")
    if not isinstance(doc.get("source_digest"), str) or not doc.get("source_digest"):
        errors.append("source_digest must be a non-empty string")
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("entries must be a non-empty list (a feed with zero entries checks nothing)")
        entries = []
    keys = response_keys()
    seen = {}
    for i, e in enumerate(entries):
        eid = check_entry(e, i, month, keys, errors)
        if isinstance(eid, str):
            if eid in seen:
                errors.append(f"duplicate id {eid} at entries[{seen[eid]}] and entries[{i}]")
            seen.setdefault(eid, i)
    return {"file": path, "ok": not errors, "entries": len(entries), "errors": errors}


def main(argv) -> int:
    files = [a for a in argv if a != "--json"]
    if not files or any(f.startswith("-") for f in files):
        raise C.UsageError("usage: validate_feed.py <feed.json> [<feed.json> ...]")
    results = [validate(f) for f in files]
    ok = all(r["ok"] for r in results)
    C.emit({"tool": "validate_feed", "ok": ok, "results": results})
    return 0 if ok else 1


if __name__ == "__main__":
    C.run_main(main)
