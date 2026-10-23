#!/usr/bin/env python3
"""PYA scoring: category scores, overall score, grade and caps.

Usage: python3 -I score.py <findings.json | - | --data '<json>'> [--json]
                           [--files-in-scope N] [--files-reviewed N] [--kev-matches N]

Input ("-" reads stdin; --data takes the JSON as one single-line argument, which is
how the orchestrator calls it so the command matches a one-line permission rule;
the orchestrator sends only ids, severities, confidences, kev flags and coverage,
never free text, so the argument holds no quotes):
  {"agents": [<agent output per docs/architecture.md>],
   "verdicts": [<finding-verifier output>],
   "files_in_scope": N, "files_reviewed": N, "kev_matches": N}
A bare list is read as the agents list.

Rules (references/scoring-rubric.md):
- category score = 100 minus deductions, floor 0; only kept findings count;
- a verdict with keep false or confidence below 8 filters the finding; a
  verdict may carry a corrected "severity", which then applies;
- not applicable agents have their weight redistributed; an agent that is
  missing, failed or returned invalid output is unreviewed: no score, weight
  removed, never a neutral 50;
- overall = weighted mean over completed applicable agents;
- grade A >= 90, B >= 75, C >= 50, D >= 25, F below; capped at C on a kept
  CRITICAL with HIGH confidence, any KEV match, coverage below 75 percent,
  or fewer than 6 applicable agents completed.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pya_common as C  # noqa: E402

WEIGHTS = {
    "vuln-scanner": 18,
    "authz-reviewer": 14,
    "secret-scanner": 10,
    "dependency-auditor": 12,
    "iac-scanner": 9,
    "threat-intel": 13,
    "ai-code-auditor": 6,
    "logic-reviewer": 9,
    "agentic-auditor": 9,
}
DEDUCTIONS = {
    "CRITICAL": {"HIGH": 25, "MEDIUM": 15, "LOW": 7},
    "HIGH": {"HIGH": 15, "MEDIUM": 10, "LOW": 5},
    "MEDIUM": {"HIGH": 8, "MEDIUM": 5, "LOW": 2},
    "LOW": {"HIGH": 2, "MEDIUM": 2, "LOW": 1},
    "INFO": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
}
SEVERITIES = tuple(DEDUCTIONS)
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
VERIFY_MIN = 8
COVERAGE_MIN = 75.0
MIN_AGENTS = 6
CLEAN = "No findings in reviewed scope. This is not proof of absence."


def grade_for(score):
    if score is None:
        return None
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"


def cap_grade(grade):
    order = "ABCDF"
    if grade is None:
        return None
    return grade if order.index(grade) >= order.index("C") else "C"


def agent_name(raw):
    name = str(raw or "").strip()
    return name.split(":", 1)[1] if name.startswith("pya:") else name


def valid_agent_output(a):
    if not isinstance(a, dict):
        return "not an object"
    if a.get("status") in ("failed", "error", "timeout") or a.get("error"):
        return str(a.get("error") or a.get("status"))
    if not isinstance(a.get("applicable"), bool):
        return "missing applicable flag"
    if a["applicable"] and not isinstance(a.get("findings"), list):
        return "missing findings list"
    for f in a.get("findings") or []:
        if not isinstance(f, dict) or not f.get("id"):
            return "finding without id"
        if str(f.get("severity", "")).upper() not in SEVERITIES:
            return f"finding {f.get('id')} has invalid severity"
        if str(f.get("confidence", "")).upper() not in CONFIDENCES:
            return f"finding {f.get('id')} has invalid confidence"
    return None


def index_verdicts(verdicts):
    by_pair, by_id = {}, {}
    for v in verdicts or []:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        if v.get("agent"):
            by_pair[(agent_name(v["agent"]), v["id"])] = v
        by_id.setdefault(v["id"], v)
    return by_pair, by_id


def score(doc, overrides):
    if isinstance(doc, list):
        doc = {"agents": doc}
    if not isinstance(doc, dict):
        raise C.UsageError("input must be a JSON object or a list of agent outputs")
    agents_in = doc.get("agents") or []
    by_pair, by_id = index_verdicts(doc.get("verdicts"))

    outputs = {}
    invalid = {}
    for a in agents_in:
        name = agent_name(a.get("agent") if isinstance(a, dict) else None)
        if name not in WEIGHTS:
            continue
        problem = valid_agent_output(a)
        if problem:
            invalid[name] = problem
        else:
            outputs[name] = a

    categories, kept, filtered, unverified = [], [], [], []
    unreviewed, not_applicable = [], []
    critical_high, kev_ids = [], []
    sum_in_scope = sum_reviewed = 0

    skipped_in = doc.get("skipped") or {}
    if isinstance(skipped_in, list):
        skipped_in = {str(s): "skipped by scope" for s in skipped_in}
    skipped_in = {agent_name(k): str(v) for k, v in skipped_in.items() if isinstance(k, str)}
    skipped = []

    for name, weight in WEIGHTS.items():
        if name not in outputs and name not in invalid and name in skipped_in:
            # Deliberately not dispatched (scope, --focus, or area absent): not a failure.
            skipped.append({"agent": name, "reason": skipped_in[name]})
            categories.append({"agent": name, "score": None, "weight": weight, "status": "skipped",
                               "reason": skipped_in[name]})
            continue
        if name not in outputs:
            reason = invalid.get(name, "no output")
            unreviewed.append({"agent": name, "reason": reason})
            categories.append({"agent": name, "score": None, "weight": weight, "status": "unreviewed",
                               "reason": reason})
            continue
        a = outputs[name]
        if not a["applicable"]:
            not_applicable.append(name)
            categories.append({"agent": name, "score": None, "weight": weight, "status": "not_applicable"})
            continue
        cov = a.get("coverage") or {}
        if isinstance(cov.get("files_in_scope"), int) and isinstance(cov.get("files_reviewed"), int):
            sum_in_scope += cov["files_in_scope"]
            sum_reviewed += min(cov["files_reviewed"], cov["files_in_scope"])
        total = 0
        n_kept = 0
        for f in a.get("findings") or []:
            fid = f["id"]
            sev = str(f["severity"]).upper()
            conf = str(f["confidence"]).upper()
            v = by_pair.get((name, fid)) or by_id.get(fid)
            if v is not None:
                vconf = v.get("confidence")
                if v.get("keep") is False:
                    filtered.append({"id": fid, "agent": name, "reason": v.get("justification") or "verifier: keep false"})
                    continue
                if not isinstance(vconf, (int, float)) or vconf < VERIFY_MIN:
                    filtered.append({"id": fid, "agent": name,
                                     "reason": f"verifier confidence {vconf} below {VERIFY_MIN}: "
                                               + str(v.get("justification") or "")})
                    continue
                if str(v.get("severity", "")).upper() in SEVERITIES:
                    sev = str(v["severity"]).upper()
            elif sev in ("CRITICAL", "HIGH"):
                unverified.append(fid)
            total += DEDUCTIONS[sev][conf]
            n_kept += 1
            kept.append(fid)
            if sev == "CRITICAL" and conf == "HIGH":
                critical_high.append(fid)
            if f.get("kev") is True:
                kev_ids.append(fid)
        categories.append({"agent": name, "score": max(0, 100 - total), "weight": weight, "status": "scored",
                           "deductions": total, "findings_kept": n_kept})

    scored = [c for c in categories if c["status"] == "scored"]
    weight_sum = sum(c["weight"] for c in scored)
    weights_effective = {}
    overall = None
    if weight_sum:
        for c in scored:
            weights_effective[c["agent"]] = round(c["weight"] * 100.0 / weight_sum, 2)
        overall = round(sum(c["score"] * c["weight"] for c in scored) / weight_sum, 1)

    in_scope = overrides.get("files_in_scope", doc.get("files_in_scope"))
    reviewed = overrides.get("files_reviewed", doc.get("files_reviewed"))
    if not isinstance(in_scope, int) or not isinstance(reviewed, int):
        in_scope, reviewed = sum_in_scope, sum_reviewed
    coverage_pct = round(min(reviewed, in_scope) * 100.0 / in_scope, 1) if in_scope > 0 else None

    kev_matches = overrides.get("kev_matches", doc.get("kev_matches")) or 0
    if not isinstance(kev_matches, int):
        kev_matches = 0

    caps = []
    if critical_high:
        caps.append(f"Grade capped at C: kept CRITICAL finding with HIGH confidence ({', '.join(critical_high[:10])})")
    if kev_matches or kev_ids:
        what = f"{kev_matches} feed match(es)" if kev_matches else ""
        ids = ", ".join(kev_ids[:10])
        caps.append("Grade capped at C: CISA KEV match (" + "; ".join(p for p in (what, ids) if p) + ")")
    if coverage_pct is None:
        caps.append("Grade capped at C: coverage could not be measured (no files in scope reported)")
    elif coverage_pct < COVERAGE_MIN:
        caps.append(f"Grade capped at C: coverage {coverage_pct}% is below {COVERAGE_MIN:.0f}% of files in scope")
    dispatched = len(scored) + len(unreviewed)
    if unreviewed and (len(scored) < MIN_AGENTS or len(unreviewed) * 4 > dispatched):
        caps.append(f"Grade capped at C: only {len(scored)} of {dispatched} dispatched agents completed "
                    f"({len(unreviewed)} unreviewed)")

    grade_uncapped = grade_for(overall)
    grade = cap_grade(grade_uncapped) if caps else grade_uncapped
    return {
        "tool": "score",
        "overall": overall,
        "grade": grade,
        "grade_uncapped": grade_uncapped,
        "caps": caps,
        "categories": categories,
        "weights_effective": weights_effective,
        "coverage_pct": coverage_pct,
        "coverage": {"files_in_scope": in_scope, "files_reviewed": reviewed},
        "unreviewed": unreviewed,
        "not_applicable": not_applicable,
        "skipped": skipped,
        "agents_completed": len(scored),
        "kept": kept,
        "filtered": filtered,
        "unverified_high": unverified,
        "kev_matches": kev_matches + len(kev_ids),
        "summary": CLEAN if not kept else f"{len(kept)} kept finding(s)",
    }


def main(argv) -> int:
    args = [a for a in argv if a != "--json"]
    overrides = {}
    for flag, key in (("--files-in-scope", "files_in_scope"), ("--files-reviewed", "files_reviewed"),
                      ("--kev-matches", "kev_matches")):
        if flag in args:
            i = args.index(flag)
            try:
                overrides[key] = int(args[i + 1])
            except (IndexError, ValueError):
                raise C.UsageError(f"{flag} needs an integer")
            del args[i:i + 2]
    data = None
    if "--data" in args:
        i = args.index("--data")
        try:
            data = args[i + 1]
        except IndexError:
            raise C.UsageError("--data needs a JSON string")
        del args[i:i + 2]
        args.append("--data")
    if len(args) != 1:
        raise C.UsageError("usage: score.py <findings.json | - | --data '<json>'> [--files-in-scope N] "
                           "[--files-reviewed N] [--kev-matches N]")
    src = args[0]
    try:
        if src == "--data":
            doc = json.loads(data)
        elif src == "-":
            doc = json.load(sys.stdin)
        else:
            with open(src, encoding="utf-8") as fh:
                doc = json.load(fh)
    except ValueError as exc:
        raise C.UsageError(f"input is not valid JSON: {exc}")
    except OSError as exc:
        raise C.UsageError(f"cannot read input: {exc}")
    C.emit(score(doc, overrides))
    return 0


if __name__ == "__main__":
    C.run_main(main)
