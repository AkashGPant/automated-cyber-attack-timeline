from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str

    host: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    parent_process_id: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    file_path: Optional[str] = None
    command_line: Optional[str] = None
    domain: Optional[str] = None
    description: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    bytes_transferred: Optional[int] = None
    registry_key: Optional[str] = None
    logon_type: Optional[str] = None
    source_file: Optional[str] = None
    row_number: Optional[int] = None

    severity: str = "INFO"
    risk_score: int = 0
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None

    # Enrichment populated by the analysis pipeline
    detection_ids: List[str] = field(default_factory=list)
    rule_names: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    incident_id: Optional[str] = None
    risk_explanation: List[str] = field(default_factory=list)

    raw_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def evidence_ref(self) -> str:
        """Stable pointer back to the original evidence row."""
        if self.source_file:
            return f"{self.source_file}#row{self.row_number}"
        return self.event_id

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "username": self.username,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process": self.parent_process,
            "parent_process_id": self.parent_process_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "domain": self.domain,
            "file_path": self.file_path,
            "registry_key": self.registry_key,
            "command_line": self.command_line,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique": self.mitre_technique,
            "rules": "; ".join(self.rule_names),
            "detection_ids": "; ".join(self.detection_ids),
            "iocs": "; ".join(self.iocs),
            "incident_id": self.incident_id,
            "risk_explanation": " | ".join(self.risk_explanation),
            "evidence_ref": self.evidence_ref,
        }
