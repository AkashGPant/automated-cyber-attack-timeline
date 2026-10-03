from typing import List
from models.event_model import NormalizedEvent
from config.config import RISK_LOW, RISK_MEDIUM, RISK_HIGH

class RiskScoringEngine:
    def calculate_risk(self, events: List[NormalizedEvent]):
        for event in events:
            if event.risk_score == 0:
                event.severity = "INFO"
            elif event.risk_score < RISK_LOW:
                event.severity = "LOW"
            elif event.risk_score < RISK_MEDIUM:
                event.severity = "MEDIUM"
            elif event.risk_score < RISK_HIGH:
                event.severity = "HIGH"
            else:
                event.severity = "CRITICAL"
        return events
