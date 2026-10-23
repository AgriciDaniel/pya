#!/usr/bin/env python3
"""Refresh the local CISA KEV snapshot used by feed_match.py. OPT-IN NETWORK.

Usage: python3 -I update_kev.py [--json] [--output PATH] [--from-file PATH]

Running this script is the opt-in: it downloads the CISA Known Exploited
Vulnerabilities catalog over HTTPS and stores a slim snapshot (catalog
version, release date and per-CVE dates) at ~/.cache/pya/kev.json, or
$XDG_CACHE_HOME/pya/kev.json. Nothing about the scanned repository is
sent. --from-file imports a catalog file you already have instead of
downloading. No other script in PYA touches the network.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 64 * 1024 * 1024
TIMEOUT = 60


def default_output():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "pya", "kev.json")


def fetch(url=KEV_URL):
    if not url.startswith("https://"):
        raise C.UsageError("refusing a non-https KEV URL")
    req = urllib.request.Request(url, headers={"User-Agent": "pya-update-kev/2", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (https enforced above)
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("KEV catalog larger than the size cap")
    return data


def slim(raw: bytes, source: str):
    doc = json.loads(raw.decode("utf-8"))
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list) or not doc.get("catalogVersion"):
        raise ValueError("not a CISA KEV catalog (missing catalogVersion or vulnerabilities)")
    cves = {}
    for v in vulns:
        cve = v.get("cveID")
        if isinstance(cve, str) and cve.startswith("CVE-"):
            cves[cve] = {
                "dateAdded": v.get("dateAdded"),
                "dueDate": v.get("dueDate"),
                "vendorProject": v.get("vendorProject"),
                "product": v.get("product"),
                "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
            }
    if not cves:
        raise ValueError("KEV catalog has zero CVEs")
    return {
        "catalogVersion": doc.get("catalogVersion"),
        "dateReleased": doc.get("dateReleased"),
        "count": len(cves),
        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "cves": cves,
    }


def write_atomic(path, obj):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kev.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, separators=(",", ":"))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv) -> int:
    args = [a for a in argv if a != "--json"]
    output, from_file = default_output(), None
    for flag in ("--output", "--from-file"):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                raise C.UsageError(f"{flag} needs a path")
            if flag == "--output":
                output = args[i + 1]
            else:
                from_file = args[i + 1]
            del args[i:i + 2]
    if args:
        raise C.UsageError("usage: update_kev.py [--json] [--output PATH] [--from-file PATH]")
    previous = None
    if os.path.isfile(output):
        try:
            with open(output, encoding="utf-8") as fh:
                previous = json.load(fh).get("catalogVersion")
        except (OSError, ValueError):
            previous = None
    try:
        if from_file:
            with open(from_file, "rb") as fh:
                raw = fh.read(MAX_BYTES + 1)
            source = os.path.abspath(from_file)
        else:
            raw = fetch()
            source = KEV_URL
        snap = slim(raw, source)
    except (OSError, ValueError) as exc:
        C.emit({"tool": "update_kev", "status": "failed", "reason": f"{type(exc).__name__}: {exc}",
                "output": output, "previous_catalogVersion": previous})
        return 1
    write_atomic(output, snap)
    C.emit({
        "tool": "update_kev", "status": "updated", "output": output, "source": source,
        "catalogVersion": snap["catalogVersion"], "dateReleased": snap["dateReleased"],
        "count": snap["count"], "previous_catalogVersion": previous,
    })
    return 0


if __name__ == "__main__":
    C.run_main(main)
