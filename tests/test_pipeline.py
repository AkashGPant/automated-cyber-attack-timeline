import os

import pytest

from core.pipeline import analyze_files
from core.risk_scoring import RiskScoringEngine, score_to_severity
from ioc.extractor import IOCExtractor
from reports.report_generator import ReportGenerator
from scripts.generate_sample_data import generate


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    out = tmp_path_factory.mktemp("sample")
    generate(seed=1337, out_dir=str(out))
    paths = [os.path.join(out, f) for f in sorted(os.listdir(out)) if f.endswith(".csv")]
    return analyze_files(paths)


def test_sample_pipeline_runs(result):
    assert result.summary["total_events"] > 100
    assert not result.rule_errors


def test_multistage_incident_detected(result):
    # scenario A should become a high-risk multi-tactic incident
    top = max(result.incidents, key=lambda i: i.score)
    assert top.score >= 80 and top.severity in ("HIGH", "CRITICAL")
    assert len(top.tactics) >= 4
    assert any("Brute force" in p or "Command and Control" in p or "exfiltration" in p.lower()
               for p in top.patterns) or len(top.techniques) >= 5


def test_expected_techniques_present(result):
    found = {d.technique_id for d in result.detections}
    for tid in ("T1110.001", "T1059.001", "T1105", "T1547.001", "T1003.001", "T1071.001"):
        assert tid in found, tid


def test_iocs_extracted_and_scoped(result):
    values = {i["IOC"] for i in result.iocs}
    assert "203.0.113.45" in values
    assert "198.51.100.23" in values
    assert any(i["malicious_context"] for i in result.iocs)
    # internal/allowlisted addresses are not promoted as external IOCs
    assert all(i["scope"] != "internal" or i["Type"].startswith("IP") for i in result.iocs)


def test_benign_microsoft_not_malicious_ioc(result):
    for i in result.iocs:
        if i["IOC"] == "update.microsoft.com":
            assert not i["malicious_context"]


def test_risk_scores_bounded(result):
    for d in result.detections:
        assert 0 <= d.score <= 100
    for inc in result.incidents:
        assert 0 <= inc.score <= 100
        assert inc.score_explanation


def test_no_double_counting():
    from models.detection_model import Detection
    from datetime import datetime
    eng = RiskScoringEngine()

    class Inc:
        pass
    inc = Inc()
    d1 = Detection("D1", "R", "r", "T1059.001", "PowerShell", "Execution", "HIGH", 0.9,
                   datetime(2026, 1, 1), "x")
    d2 = Detection("D2", "R", "r", "T1059.001", "PowerShell", "Execution", "HIGH", 0.9,
                   datetime(2026, 1, 1), "x")  # same technique repeated
    inc.detections = [d1, d2]
    inc.tactics = ["Execution"]
    inc.patterns = []
    inc.sources = ["Sysmon"]
    one = Detection("D3", "R", "r", "T1059.001", "PowerShell", "Execution", "HIGH", 0.9,
                    datetime(2026, 1, 1), "x")
    inc_single = Inc()
    inc_single.detections = [one]
    inc_single.tactics = ["Execution"]
    inc_single.patterns = []
    inc_single.sources = ["Sysmon"]
    assert eng.score_incident(inc) == eng.score_incident(inc_single)


def test_score_to_severity_bands():
    assert score_to_severity(0) == "INFO"
    assert score_to_severity(29) == "LOW"
    assert score_to_severity(59) == "MEDIUM"
    assert score_to_severity(79) == "HIGH"
    assert score_to_severity(90) == "CRITICAL"


def test_report_generation(result, tmp_path):
    gen = ReportGenerator(output_dir=str(tmp_path))
    paths = gen.generate_all(result)
    assert all(os.path.exists(p) for p in paths.values())
    report = gen.build_report(result)
    assert report["incidents"] and report["executive_summary"]["narrative"]
    assert report["report_metadata"]["report_version"]
    zbytes = gen.build_zip(result)
    assert zbytes[:2] == b"PK"


def test_process_trees_built(result):
    assert result.process_trees
    flagged = [n for nodes in result.process_trees.values() for n in nodes if n.detection_ids]
    assert flagged
