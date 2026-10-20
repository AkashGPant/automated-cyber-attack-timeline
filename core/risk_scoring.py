"""Explainable 0-100 risk scoring.

Detection score  = severity base x (0.5 + 0.5 x confidence)
Event score      = strongest detection + 10% of each *other distinct technique* (max +15)
Incident score   = strongest detection
                   + 4 per additional distinct tactic (max +20)
                   + 10 if a known attack pattern matched / +5 if >=3 tactics without a pattern
                   + 5 if corroborated by >=2 log sources
All capped at 100. Repeats of the same technique never add score (no double counting).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from config.config import RISK_HIGH, RISK_LOW, RISK_MEDIUM
from models.detection_model import Detection
from models.event_model import NormalizedEvent

SEVERITY_BASE = {"INFO": 0, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}


def score_to_severity(score: float) -> str:
    if score <= 0:
        return "INFO"
    if score < RISK_LOW:
        return "LOW"
    if score < RISK_MEDIUM:
        return "MEDIUM"
    if score < RISK_HIGH:
        return "HIGH"
    return "CRITICAL"


class RiskScoringEngine:
    def score_detection(self, d: Detection) -> int:
        base = SEVERITY_BASE.get(d.severity, 0)
        factor = 0.5 + 0.5 * max(0.0, min(d.confidence, 1.0))
        d.score = int(round(min(100, base * factor)))
        d.score_explanation = [f"{d.severity} severity base {base} × confidence factor {factor:.2f} "
                               f"(confidence {d.confidence:.2f}) = {d.score}"]
        return d.score

    def calculate_risk(self, events: List[NormalizedEvent], detections: Optional[List[Detection]] = None,
                       incidents: Optional[list] = None):
        """Score detections, events and incidents. Without detections the legacy
        behaviour (severity derived from an existing ``risk_score``) is kept."""
        if detections is None:
            for event in events:
                event.severity = score_to_severity(event.risk_score)
            return events

        for d in detections:
            self.score_detection(d)
        det_by_id: Dict[str, Detection] = {d.detection_id: d for d in detections}

        for event in events:
            dets = [det_by_id[i] for i in event.detection_ids if i in det_by_id]
            if not dets:
                event.risk_score, event.severity, event.risk_explanation = 0, "INFO", []
                continue
            event.risk_score, event.risk_explanation = self._combine(dets)
            event.severity = score_to_severity(event.risk_score)

        for inc in incidents or []:
            self.score_incident(inc)
        return events

    @staticmethod
    def _combine(dets: List[Detection]):
        best_per_tech: Dict[str, Detection] = {}
        for d in dets:
            if d.technique_id not in best_per_tech or d.score > best_per_tech[d.technique_id].score:
                best_per_tech[d.technique_id] = d
        ranked = sorted(best_per_tech.values(), key=lambda d: d.score, reverse=True)
        top = ranked[0]
        bonus = min(15, sum(round(0.1 * d.score) for d in ranked[1:]))
        score = min(100, top.score + bonus)
        expl = [f"Strongest: {top.technique_id} {top.rule_name} = {top.score}"]
        if bonus:
            expl.append(f"+{bonus} for {len(ranked) - 1} additional distinct technique(s) (10% each, max 15)")
        dup = len(dets) - len(ranked)
        if dup:
            expl.append(f"{dup} repeated technique hit(s) not counted again")
        return score, expl

    def score_incident(self, inc) -> int:
        for d in inc.detections:
            if not d.score:
                self.score_detection(d)
        top = max(inc.detections, key=lambda d: d.score)
        expl = [f"Base: strongest detection {top.technique_id} ({top.rule_name}) = {top.score}"]
        score = top.score
        extra_tactics = max(0, len(inc.tactics) - 1)
        tactic_bonus = min(20, 4 * extra_tactics)
        if tactic_bonus:
            score += tactic_bonus
            expl.append(f"+{tactic_bonus}: {extra_tactics} additional ATT&CK tactic(s) "
                        f"({', '.join(inc.tactics)})")
        if inc.patterns:
            score += 10
            expl.append(f"+10: matched attack pattern '{inc.patterns[0]}'")
        elif len(inc.tactics) >= 3:
            score += 5
            expl.append("+5: multi-stage progression across ≥3 tactics")
        if len(inc.sources) >= 2:
            score += 5
            expl.append(f"+5: corroborated by {len(inc.sources)} log sources ({', '.join(inc.sources)})")
        repeats = len(inc.detections) - len({d.technique_id for d in inc.detections})
        if repeats:
            expl.append(f"{repeats} repeated technique detection(s) not counted again")
        inc.score = int(min(100, score))
        if score > 100:
            expl.append("Capped at 100")
        inc.severity = score_to_severity(inc.score)
        inc.score_explanation = expl
        return inc.score
