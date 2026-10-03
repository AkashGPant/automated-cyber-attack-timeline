from dataclasses import dataclass, field
from typing import Optional, Dict, Any
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
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    file_path: Optional[str] = None
    command_line: Optional[str] = None
    domain: Optional[str] = None
    description: Optional[str] = None
    
    severity: str = "INFO"
    risk_score: int = 0
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "username": self.username,
            "process_name": self.process_name,
            "parent_process": self.parent_process,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "command_line": self.command_line,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique": self.mitre_technique
        }
