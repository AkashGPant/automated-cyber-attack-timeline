from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from config.detection_config import load_rule_config
from detection.rules import AGGREGATE_RULES, EVENT_RULES
from models.detection_model import Detection, severity_rank
from models.event_model import NormalizedEvent

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config if config is not None else load_rule_config()
        self.rules = [r(self.config) for r in EVENT_RULES]
        self.aggregate_rules = [r(self.config) for r in AGGREGATE_RULES]
        self.detections: List[Detection] = []
        self.rule_errors: List[str] = []

    def scan(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        """Run all enabled rules; annotate events and keep detections in ``self.detections``."""
        self.detections, self.rule_errors = [], []
        for rule in self.rules:  # clear any per-scan state (e.g. connection aggregation)
            reset = getattr(rule, "reset", None)
            if callable(reset):
                reset()
        context: Dict[str, Any] = {}
        dets: List[Detection] = []
        for event in events:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                try:
                    dets.extend(rule.evaluate(event) or [])
                except Exception as exc:
                    self._rule_failed(rule, exc)
        for rule in self.aggregate_rules:
            if not rule.enabled:
                continue
            try:
                dets.extend(rule.evaluate_all(events, context) or [])
            except Exception as exc:
                self._rule_failed(rule, exc)
        self.detections = self._filter(self._dedupe(dets))
        self.detections.sort(key=lambda d: d.timestamp)
        self._annotate(events)
        return events

    def run(self, events: List[NormalizedEvent]):
        self.scan(events)
        return events, self.detections

    # ------------------------------------------------------------------ internals
    def _rule_failed(self, rule, exc):
        msg = f"Rule {rule.rule_id} failed: {exc}"
        if msg not in self.rule_errors:
            self.rule_errors.append(msg)
            logger.warning(msg)

    @staticmethod
    def _dedupe(dets: List[Detection]) -> List[Detection]:
        """Collapse the same technique on the same activity seen by two log sources
        (e.g. Sysmon EID 1 and Security 4688 for one process)."""
        kept: Dict[tuple, Detection] = {}
        for d in dets:
            ev = " ".join(d.evidence[1:2]).lower()
            key = (d.technique_id, (d.host or "").lower(), ev, d.timestamp.replace(microsecond=0)
                   .isoformat()[:-1])  # 10-second bucket
            if key in kept:
                k = kept[key]
                k.event_ids = list(dict.fromkeys(k.event_ids + d.event_ids))
                k.evidence_refs = list(dict.fromkeys(k.evidence_refs + d.evidence_refs))
                if d.confidence > k.confidence:
                    k.confidence = d.confidence
            else:
                kept[key] = d
        return list(kept.values())

    def _filter(self, dets: List[Detection]) -> List[Detection]:
        g = self.config.get("global", {})
        users = {u.lower() for u in g.get("allowlisted_users", [])}
        hosts = {h.lower() for h in g.get("allowlisted_hosts", [])}
        return [d for d in dets
                if (d.user or "").lower() not in users and (d.host or "").lower() not in hosts]

    def _annotate(self, events: List[NormalizedEvent]):
        by_id = {e.event_id: e for e in events}
        for d in self.detections:
            for eid in d.event_ids:
                e = by_id.get(eid)
                if e is None:
                    continue
                if d.detection_id not in e.detection_ids:
                    e.detection_ids.append(d.detection_id)
                if d.rule_name not in e.rule_names:
                    e.rule_names.append(d.rule_name)
                current = severity_rank(e.severity) if e.mitre_technique_id else -1
                if severity_rank(d.severity) > current:
                    e.mitre_technique_id = d.technique_id
                    e.mitre_technique = d.technique_name
                    e.mitre_tactic = d.tactic
                    e.severity = d.severity
