#!/usr/bin/env python3
"""Run optional external scanners if they are installed. Offline by default.

Usage: python3 -I run_tools.py <target> [--json] [--online] [--timeout SECONDS]
                                         [--only osv-scanner,trufflehog,zizmor,semgrep]
                                         [--semgrep-config PATH]

Tools are found on PATH and never installed. Each one runs with fixed
arguments, no shell, a timeout, and a scratch working directory:
  osv-scanner  scan source -r --format json --offline-vulnerabilities <t>
               (only when a local vulnerability database exists)
  trufflehog   filesystem <t> --json --no-verification --no-update
  zizmor       --offline --format json <t>
  semgrep      scan --json --metrics=off --disable-version-check --config <local>
               (only with a local config from --semgrep-config or PYA_SEMGREP_CONFIG)
--online enables osv-scanner online lookups and trufflehog verification
(which sends candidate secrets to their providers). Status per tool is
ran, not_installed, not_run or failed, with a reason. A tool that did not
run is never reported as clean. Output is compact JSON; secrets are masked.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

TOOLS = ("osv-scanner", "trufflehog", "zizmor", "semgrep")
MAX_OUT = 64 * 1024 * 1024
LIST_CAP = 50


def run(cmd, timeout, cwd):
    env = dict(os.environ)
    env.setdefault("NO_COLOR", "1")
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        return None, b"", b"", f"could not start: {exc}"
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:  # kill the whole process group so helpers do not linger
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        proc.communicate()
        return None, b"", b"", f"timed out after {timeout}s"
    return proc.returncode, out[:MAX_OUT], err[-4000:], None


def stderr_tail(err: bytes) -> str:
    return C.redact(err.decode("utf-8", "replace").strip().splitlines()[-1] if err.strip() else "", 300)


# --------------------------------------------------------------------------
# osv-scanner
# --------------------------------------------------------------------------

def osv_db_dir():
    env = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
    candidates = [env] if env else []
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    candidates.append(os.path.join(base, "osv-scanner"))
    for c in candidates:
        if c and os.path.isdir(c):
            try:
                if any(os.scandir(c)):
                    return c
            except OSError:
                continue
    return None


def summarize_osv(out: bytes):
    data = json.loads(out.decode("utf-8") or "{}")
    vulns, malicious = [], []
    packages = 0
    for res in data.get("results", []) or []:
        source = (res.get("source") or {}).get("path")
        for pkg in res.get("packages", []) or []:
            packages += 1
            info = pkg.get("package") or {}
            for v in pkg.get("vulnerabilities", []) or []:
                vid = v.get("id", "")
                item = {"id": vid, "aliases": (v.get("aliases") or [])[:5], "package": info.get("name"),
                        "version": info.get("version"), "ecosystem": info.get("ecosystem"),
                        "source": os.path.basename(source or "")}
                (malicious if vid.startswith("MAL-") else vulns).append(item)
    return {"packages_with_findings": packages, "vulnerabilities": len(vulns), "malicious": len(malicious),
            "items": (malicious + vulns)[:LIST_CAP]}


def run_osv(exe, target, online, timeout, cwd):
    cmd = [exe, "scan", "source", "-r", "--format", "json"]
    if not online:
        db = osv_db_dir()
        if not db:
            return {"status": "not_run",
                    "reason": "no local OSV database; run osv-scanner --download-offline-databases once, or pass --online"}
        cmd.append("--offline-vulnerabilities")
    cmd.append(target)
    code, out, err, problem = run(cmd, timeout, cwd)
    base = {"command": " ".join(cmd[1:-1]) + " <target>", "mode": "online" if online else "offline"}
    if problem:
        return {**base, "status": "failed", "reason": problem}
    if code == 128:
        return {**base, "status": "ran", "exit_code": code,
                "summary": {"note": "exit 128: no packages found, which is not the same as clean"}}
    if code not in (0, 1):
        return {**base, "status": "failed", "exit_code": code, "reason": stderr_tail(err)}
    try:
        return {**base, "status": "ran", "exit_code": code, "summary": summarize_osv(out)}
    except ValueError:
        return {**base, "status": "failed", "exit_code": code, "reason": "output was not JSON"}


# --------------------------------------------------------------------------
# trufflehog
# --------------------------------------------------------------------------

def summarize_trufflehog(out: bytes, target: str):
    items, detectors = [], {}
    verified = 0
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if "DetectorName" not in rec:
            continue
        name = rec.get("DetectorName")
        detectors[name] = detectors.get(name, 0) + 1
        verified += 1 if rec.get("Verified") else 0
        fs = (((rec.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        path = fs.get("file") or ""
        if path.startswith(target):
            path = os.path.relpath(path, target)
        raw = rec.get("Raw") or ""
        if len(items) < LIST_CAP:
            items.append({"detector": name, "verified": bool(rec.get("Verified")), "file": path,
                          "line": fs.get("line"), "redacted": C.mask(raw) if raw else None})
    return {"results": sum(detectors.values()), "verified": verified, "by_detector": detectors, "items": items}


def run_trufflehog(exe, target, online, timeout, cwd):
    cmd = [exe, "filesystem", target, "--json", "--no-update"]
    if not online:
        cmd.append("--no-verification")
    code, out, err, problem = run(cmd, timeout, cwd)
    base = {"command": "filesystem <target> " + " ".join(cmd[3:]), "mode": "online" if online else "offline"}
    if problem:
        return {**base, "status": "failed", "reason": problem}
    if code not in (0, 183):
        return {**base, "status": "failed", "exit_code": code, "reason": stderr_tail(err)}
    return {**base, "status": "ran", "exit_code": code, "summary": summarize_trufflehog(out, target)}


# --------------------------------------------------------------------------
# zizmor
# --------------------------------------------------------------------------

def summarize_zizmor(out: bytes):
    data = json.loads(out.decode("utf-8") or "[]")
    by_audit, by_sev, items = {}, {}, []
    for f in data if isinstance(data, list) else []:
        ident = f.get("ident") or f.get("audit") or "?"
        sev = ((f.get("determinations") or {}).get("severity")) or f.get("severity") or "?"
        by_audit[ident] = by_audit.get(ident, 0) + 1
        by_sev[sev] = by_sev.get(sev, 0) + 1
        loc = {}
        for l in f.get("locations", []) or []:
            sym = ((l.get("symbolic") or {}).get("key") or {})
            given = sym.get("Local", {}).get("given_path") if isinstance(sym.get("Local"), dict) else None
            point = (((l.get("concrete") or {}).get("location") or {}).get("start_point") or {})
            loc = {"file": given, "line": (point.get("row") + 1) if isinstance(point.get("row"), int) else None}
            break
        if len(items) < LIST_CAP:
            items.append({"audit": ident, "severity": sev, **loc})
    return {"findings": sum(by_audit.values()), "by_audit": by_audit, "by_severity": by_sev, "items": items}


def run_zizmor(exe, target, online, timeout, cwd):
    cmd = [exe, "--format", "json"]
    if not online:
        cmd.insert(1, "--offline")
    cmd.append(target)
    code, out, err, problem = run(cmd, timeout, cwd)
    base = {"command": " ".join(cmd[1:-1]) + " <target>", "mode": "online" if online else "offline"}
    if problem:
        return {**base, "status": "failed", "reason": problem}
    if code is not None and code not in (0,) and not (10 <= code <= 14):
        if b"no inputs" in err.lower() or b"no workflow" in err.lower():
            return {**base, "status": "not_run", "reason": "no GitHub Actions workflows found"}
        return {**base, "status": "failed", "exit_code": code, "reason": stderr_tail(err)}
    try:
        return {**base, "status": "ran", "exit_code": code, "summary": summarize_zizmor(out)}
    except ValueError:
        return {**base, "status": "failed", "exit_code": code, "reason": "output was not JSON"}


# --------------------------------------------------------------------------
# semgrep
# --------------------------------------------------------------------------

def run_semgrep(exe, target, online, timeout, cwd, config):
    if not config:
        return {"status": "not_run",
                "reason": "no local semgrep config; pass --semgrep-config PATH or set PYA_SEMGREP_CONFIG (registry rules are never fetched)"}
    if not os.path.exists(config):
        return {"status": "not_run", "reason": "semgrep config path does not exist"}
    cmd = [exe, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--config", config, target]
    code, out, err, problem = run(cmd, timeout, cwd)
    base = {"command": "scan --json --quiet --metrics=off --disable-version-check --config <local> <target>",
            "mode": "offline"}
    if problem:
        return {**base, "status": "failed", "reason": problem}
    if code not in (0, 1):
        return {**base, "status": "failed", "exit_code": code, "reason": stderr_tail(err)}
    try:
        data = json.loads(out.decode("utf-8") or "{}")
    except ValueError:
        return {**base, "status": "failed", "exit_code": code, "reason": "output was not JSON"}
    by_rule, items = {}, []
    for r in data.get("results", []) or []:
        rid = r.get("check_id", "?")
        by_rule[rid] = by_rule.get(rid, 0) + 1
        if len(items) < LIST_CAP:
            path = r.get("path", "")
            if path.startswith(target):
                path = os.path.relpath(path, target)
            items.append({"rule": rid, "file": path, "line": (r.get("start") or {}).get("line"),
                          "severity": (r.get("extra") or {}).get("severity")})
    return {**base, "status": "ran", "exit_code": code,
            "summary": {"findings": sum(by_rule.values()), "by_rule": by_rule, "errors": len(data.get("errors", []) or []),
                        "items": items}}


def main(argv) -> int:
    args = [a for a in argv if a != "--json"]
    online = "--online" in args
    args = [a for a in args if a != "--online"]
    opts = {"--timeout": "300", "--only": ",".join(TOOLS), "--semgrep-config": os.environ.get("PYA_SEMGREP_CONFIG")}
    for flag in list(opts):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                raise C.UsageError(f"{flag} needs a value")
            opts[flag] = args[i + 1]
            del args[i:i + 2]
    if len(args) != 1 or args[0].startswith("-"):
        raise C.UsageError("usage: run_tools.py <target> [--json] [--online] [--timeout S] [--only a,b] [--semgrep-config PATH]")
    try:
        timeout = int(opts["--timeout"])
    except ValueError:
        raise C.UsageError("--timeout needs an integer")
    only = [t.strip() for t in opts["--only"].split(",") if t.strip()]
    unknown = [t for t in only if t not in TOOLS]
    if unknown:
        raise C.UsageError(f"unknown tool(s): {', '.join(unknown)}")
    target = C.resolve_target(args[0])
    results = {}
    with tempfile.TemporaryDirectory(prefix="pya-tools-") as cwd:
        for tool in TOOLS:
            if tool not in only:
                results[tool] = {"status": "not_run", "reason": "excluded by --only"}
                continue
            exe = shutil.which(tool)
            if not exe:
                results[tool] = {"status": "not_installed", "reason": f"{tool} not found on PATH (PYA never installs tools)"}
                continue
            if C.is_inside(target, exe):
                results[tool] = {"status": "not_run", "reason": f"{tool} on PATH resolves inside the target; refusing to run it"}
                continue
            if tool == "osv-scanner":
                res = run_osv(exe, target, online, timeout, cwd)
            elif tool == "trufflehog":
                res = run_trufflehog(exe, target, online, timeout, cwd)
            elif tool == "zizmor":
                res = run_zizmor(exe, target, online, timeout, cwd)
            else:
                res = run_semgrep(exe, target, online, timeout, cwd, opts["--semgrep-config"])
            res["path"] = exe
            results[tool] = res
    ran = [t for t, r in results.items() if r["status"] == "ran"]
    C.emit({
        "tool": "run_tools",
        "target": target,
        "mode": "online" if online else "offline",
        "tools": results,
        "ran": ran,
        "not_ran": [t for t in TOOLS if t not in ran],
        "note": "A tool that did not run is not run, never clean.",
    })
    return 0


if __name__ == "__main__":
    C.run_main(main)
