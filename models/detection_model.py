from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(str(sev).upper())
    except ValueError:
        return 0


@dataclass
class Detection:
    detection_id: str
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    confidence: float
    timestamp: datetime
    description: str
    host: Optional[str] = None
    user: Optional[str] = None
    event_ids: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)
    end_time: Optional[datetime] = None
    score: int = 0
    score_explanation: List[str] = field(default_factory=list)
    incident_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "score": self.score,
            "host": self.host,
            "user": self.user,
            "description": self.description,
            "evidence": self.evidence,
            "evidence_refs": self.evidence_refs,
            "event_ids": self.event_ids,
            "entities": {k: v for k, v in self.entities.items() if v is not None},
            "score_explanation": self.score_explanation,
        }
