"""score.py follows the scoring contract and references/scoring-rubric.md."""

import json

import pytest

from conftest import load_module, run_script

score_mod = load_module("score")
AGENTS = list(score_mod.WEIGHTS)


def agent(name, findings=(), applicable=True, in_scope=100, reviewed=100):
    return {"agent": name, "applicable": applicable,
            "coverage": {"files_in_scope": in_scope, "files_reviewed": reviewed, "not_reviewed": []},
            "findings": list(findings)}


def finding(fid, sev="HIGH", conf="HIGH", kev=False):
    return {"id": fid, "title": "t", "severity": sev, "confidence": conf, "file": "a.py", "line": 1, "kev": kev}


def all_clean(**over):
    doc = {"agents": [agent(a) for a in AGENTS], "verdicts": [], "files_in_scope": 100, "files_reviewed": 100}
    doc.update(over)
    return doc


def run(doc):
    code, out, err = run_script("score.py", "-", stdin=json.dumps(doc))
    assert code == 0, err
    return out


def test_weights_sum_to_100():
    assert sum(score_mod.WEIGHTS.values()) == 100
    assert score_mod.WEIGHTS == {"vuln-scanner": 18, "authz-reviewer": 14, "secret-scanner": 10,
                                 "dependency-auditor": 12, "iac-scanner": 9, "threat-intel": 13,
                                 "ai-code-auditor": 6, "logic-reviewer": 9, "agentic-auditor": 9}


@pytest.mark.parametrize("sev,conf,expected", [
    ("CRITICAL", "HIGH", 25), ("CRITICAL", "MEDIUM", 15), ("CRITICAL", "LOW", 7),
    ("HIGH", "HIGH", 15), ("HIGH", "MEDIUM", 10), ("HIGH", "LOW", 5),
    ("MEDIUM", "HIGH", 8), ("MEDIUM", "MEDIUM", 5), ("MEDIUM", "LOW", 2),
    ("LOW", "HIGH", 2), ("LOW", "MEDIUM", 2), ("LOW", "LOW", 1),
    ("INFO", "HIGH", 0), ("INFO", "MEDIUM", 0), ("INFO", "LOW", 0),
])
def test_deduction_table(sev, conf, expected):
    doc = all_clean()
    doc["agents"][0] = agent("vuln-scanner", [finding("F1", sev, conf)])
    doc["verdicts"] = [{"id": "F1", "keep": True, "confidence": 9}]
    out = run(doc)
    cat = [c for c in out["categories"] if c["agent"] == "vuln-scanner"][0]
    assert cat["score"] == 100 - expected


def test_low_confidence_is_half_of_medium_rounded_down():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert score_mod.DEDUCTIONS[sev]["LOW"] == score_mod.DEDUCTIONS[sev]["MEDIUM"] // 2


def test_clean_result_wording_and_grade():
    out = run(all_clean())
    assert out["overall"] == 100.0 and out["grade"] == "A" and out["caps"] == []
    assert out["summary"] == "No findings in reviewed scope. This is not proof of absence."
    assert out["coverage_pct"] == 100.0


def test_floor_at_zero():
    doc = all_clean()
    doc["agents"][0] = agent("vuln-scanner", [finding(f"F{i}", "CRITICAL", "MEDIUM") for i in range(10)])
    out = run(doc)
    assert [c for c in out["categories"] if c["agent"] == "vuln-scanner"][0]["score"] == 0


def test_critical_high_caps_at_c():
    doc = all_clean()
    doc["agents"][1] = agent("authz-reviewer", [finding("A1", "CRITICAL", "HIGH")])
    doc["verdicts"] = [{"id": "A1", "keep": True, "confidence": 9}]
    out = run(doc)
    assert out["grade_uncapped"] == "A"  # 100 - 25*14/100 = 96.5
    assert out["grade"] == "C"
    assert any(c.startswith("Grade capped at C: kept CRITICAL") for c in out["caps"])


def test_capped_grade_never_raises_lower_grade():
    doc = all_clean()
    doc["agents"] = [agent(a, [finding(f"{a}-{i}", "CRITICAL", "HIGH") for i in range(4)]) for a in AGENTS]
    out = run(doc)
    assert out["overall"] == 0.0 and out["grade"] == "F"


def test_kev_caps_from_findings_and_from_count():
    doc = all_clean()
    doc["agents"][3] = agent("dependency-auditor", [finding("D1", "MEDIUM", "HIGH", kev=True)])
    out = run(doc)
    assert out["grade"] == "C" and any("KEV" in c for c in out["caps"])
    out = run(all_clean(kev_matches=1))
    assert out["grade"] == "C" and any("KEV" in c for c in out["caps"])


def test_coverage_below_75_caps():
    out = run(all_clean(files_in_scope=100, files_reviewed=74))
    assert out["coverage_pct"] == 74.0 and out["grade"] == "C"
    assert any("coverage 74.0%" in c for c in out["caps"])
    out = run(all_clean(files_in_scope=100, files_reviewed=75))
    assert out["grade"] == "A"


def test_coverage_from_agents_when_not_given():
    doc = {"agents": [agent(a, in_scope=10, reviewed=5) for a in AGENTS]}
    out = run(doc)
    assert out["coverage_pct"] == 50.0 and out["grade"] == "C"


def test_zero_files_in_scope_caps():
    out = run(all_clean(files_in_scope=0, files_reviewed=0))
    assert out["coverage_pct"] is None
    assert any("could not be measured" in c for c in out["caps"])


def test_missing_agents_are_unreviewed_and_cap():
    doc = all_clean()
    doc["agents"] = [agent(a) for a in AGENTS[:5]]
    out = run(doc)
    assert out["agents_completed"] == 5 and out["grade"] == "C"
    assert any("only 5 of 9 dispatched agents completed" in c for c in out["caps"])


def test_skipped_by_scope_is_not_a_failure():
    doc = all_clean()
    doc["agents"] = [agent(a) for a in AGENTS[:5]]
    doc["skipped"] = {a: "--scope quick" for a in AGENTS[5:]}
    out = run(doc)
    assert out["unreviewed"] == [] and len(out["skipped"]) == len(AGENTS) - 5
    assert out["grade"] == "A" and not out["caps"]
    assert {c["status"] for c in out["categories"] if c["agent"] in AGENTS[5:]} == {"skipped"}


def test_skipped_list_form_and_one_failure_among_many():
    doc = all_clean()
    doc["agents"] = [agent(a) for a in AGENTS[:7]] + [{"agent": AGENTS[7], "status": "failed", "error": "timeout"}]
    doc["skipped"] = [AGENTS[8]]
    out = run(doc)
    assert [u["agent"] for u in out["unreviewed"]] == [AGENTS[7]]
    assert not any("dispatched agents" in c for c in out["caps"])


def test_unreviewed_agent_removed_not_scored_50():
    doc = all_clean()
    doc["agents"][0] = agent("vuln-scanner", [finding("V1", "HIGH", "HIGH")])
    doc["agents"][2] = {"agent": "secret-scanner", "status": "failed", "error": "timeout"}
    doc["agents"] = [a for a in doc["agents"] if a["agent"] != "logic-reviewer"]
    out = run(doc)
    unrev = {u["agent"] for u in out["unreviewed"]}
    assert unrev == {"secret-scanner", "logic-reviewer"}
    for c in out["categories"]:
        if c["agent"] in unrev:
            assert c["score"] is None and c["status"] == "unreviewed"
    # weighted mean over the 7 completed agents only: (85*18 + 100*(100-18-10-9)) / (100-10-9)
    expected = round((85 * 18 + 100 * 63) / 81, 1)
    assert out["overall"] == expected
    assert "secret-scanner" not in out["weights_effective"]


def test_invalid_output_is_unreviewed():
    doc = all_clean()
    doc["agents"][4] = {"agent": "iac-scanner", "applicable": True, "findings": [{"id": "X", "severity": "BAD",
                                                                                 "confidence": "HIGH"}]}
    out = run(doc)
    assert {"iac-scanner"} == {u["agent"] for u in out["unreviewed"]}


def test_redistribution_when_agentic_not_applicable():
    doc = all_clean()
    doc["agents"][-1] = agent("agentic-auditor", applicable=False)
    doc["agents"][0] = agent("vuln-scanner", [finding("V1", "HIGH", "HIGH")])
    out = run(doc)
    assert out["not_applicable"] == ["agentic-auditor"]
    assert "agentic-auditor" not in out["weights_effective"]
    assert out["weights_effective"]["vuln-scanner"] == round(18 * 100 / 91, 2)
    assert abs(sum(out["weights_effective"].values()) - 100) < 0.05
    assert out["overall"] == round((85 * 18 + 100 * 73) / 91, 1)
    assert out["agents_completed"] == 8 and out["caps"] == []


def test_verifier_filters_and_corrects():
    doc = all_clean()
    doc["agents"][0] = agent("vuln-scanner", [finding("V1", "CRITICAL", "HIGH"), finding("V2", "HIGH", "HIGH"),
                                              finding("V3", "HIGH", "MEDIUM"), finding("V4", "HIGH", "HIGH")])
    doc["verdicts"] = [
        {"id": "V1", "keep": False, "confidence": 9, "justification": "test file only"},
        {"id": "V2", "keep": True, "confidence": 7, "justification": "unclear reachability"},
        {"id": "V3", "keep": True, "confidence": 9, "severity": "MEDIUM"},
        {"id": "V4", "keep": True, "confidence": 8},
    ]
    out = run(doc)
    assert out["kept"] == ["V3", "V4"]
    assert {f["id"] for f in out["filtered"]} == {"V1", "V2"}
    cat = [c for c in out["categories"] if c["agent"] == "vuln-scanner"][0]
    assert cat["score"] == 100 - 5 - 15  # V3 corrected to MEDIUM/MEDIUM, V4 HIGH/HIGH
    assert out["caps"] == []  # the filtered CRITICAL does not cap


def test_unverified_high_listed():
    doc = all_clean()
    doc["agents"][0] = agent("vuln-scanner", [finding("V9", "HIGH", "HIGH")])
    out = run(doc)
    assert out["unverified_high"] == ["V9"] and out["kept"] == ["V9"]


def test_prefixed_agent_names_and_list_input():
    out = run([dict(agent(a), agent=f"pya:{a}") for a in AGENTS])
    assert out["agents_completed"] == 9


def test_file_input(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(all_clean()))
    code, out, _ = run_script("score.py", str(p))
    assert code == 0 and out["grade"] == "A"


def test_bad_input_is_usage_error():
    code, out, _ = run_script("score.py", "-", stdin="not json")
    assert code == 2 and out["error"] == "usage"


def test_data_argument_single_line():
    doc = all_clean()
    doc["agents"][0] = agent("vuln-scanner", [finding("V1", "HIGH", "HIGH")])
    code, out, err = run_script("score.py", "--data", json.dumps(doc))
    assert code == 0, err
    assert out["agents_completed"] == len(AGENTS) and out["overall"] < 100


def test_data_argument_requires_value():
    code, out, err = run_script("score.py", "--data")
    assert code != 0
