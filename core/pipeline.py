"""End-to-end analysis pipeline: parse → normalize/correlate → detect → IOCs →
incidents/chains → risk scoring."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from config.detection_config import load_rule_config
from core.correlation import CorrelationEngine, Incident, ProcessNode
from core.risk_scoring import RiskScoringEngine, score_to_severity
from detection.detector import DetectionEngine
from ioc.extractor import IOCExtractor
from models.detection_model import Detection
from models.event_model import NormalizedEvent
from parsers.router import ParseReport, parse_file


@dataclass
class AnalysisResult:
    events: List[NormalizedEvent] = field(default_factory=list)
    detections: List[Detection] = field(default_factory=list)
    incidents: List[Incident] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)
    process_trees: Dict[str, List[ProcessNode]] = field(default_factory=dict)
    parse_reports: List[ParseReport] = field(default_factory=list)
    rule_errors: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


def analyze_events(events: List[NormalizedEvent], config: Optional[Dict[str, Any]] = None,
                   parse_reports: Optional[List[ParseReport]] = None) -> AnalysisResult:
    config = config if config is not None else load_rule_config()
    correlator = CorrelationEngine(config)
    events = correlator.correlate(events)
    detector = DetectionEngine(config)
    detector.scan(events)
    detections = detector.detections
    iocs = IOCExtractor(config).extract(events, detections)
    trees = correlator.build_process_trees(events, detections)
    incidents = correlator.build_incidents(events, detections, trees)
    RiskScoringEngine().calculate_risk(events, detections, incidents)
    result = AnalysisResult(events=events, detections=detections, incidents=incidents, iocs=iocs,
                            process_trees=trees, parse_reports=parse_reports or [],
                            rule_errors=detector.rule_errors)
    result.summary = build_summary(result)
    return result


def analyze_files(file_paths: Iterable[str], config: Optional[Dict[str, Any]] = None) -> AnalysisResult:
    events: List[NormalizedEvent] = []
    reports: List[ParseReport] = []
    for path in file_paths:
        evs, rep = parse_file(path)
        events.extend(evs)
        reports.append(rep)
    return analyze_events(events, config, reports)


def build_summary(r: AnalysisResult) -> Dict[str, Any]:
    ev = r.events
    max_score = max((i.score for i in r.incidents), default=0)
    sev_counts = Counter(d.severity for d in r.detections)
    return {
        "total_events": len(ev),
        "events_by_source": dict(Counter(e.source for e in ev)),
        "time_range": {
            "start": ev[0].timestamp.isoformat() if ev else None,
            "end": ev[-1].timestamp.isoformat() if ev else None,
        },
        "total_detections": len(r.detections),
        "detections_by_severity": {k: sev_counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "total_incidents": len(r.incidents),
        "overall_risk_score": max_score,
        "overall_severity": score_to_severity(max_score),
        "affected_hosts": sorted({h for i in r.incidents for h in i.hosts}),
        "affected_users": sorted({u for i in r.incidents for u in i.users}),
        "techniques": sorted({d.technique_id for d in r.detections}),
        "tactics": sorted({d.tactic for d in r.detections}),
        "total_iocs": len(r.iocs),
        "malicious_iocs": sum(1 for i in r.iocs if i.get("malicious_context")),
        "parse_errors": sum(len(p.errors) for p in r.parse_reports),
        "parse_warnings": sum(len(p.warnings) for p in r.parse_reports),
    }
