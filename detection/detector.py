from typing import List
from models.event_model import NormalizedEvent
from detection.rules import SuspiciousPowerShellRule, FailedLoginRule, SuspiciousNetworkConnectionRule

class DetectionEngine:
    def __init__(self):
        self.rules = [
            SuspiciousPowerShellRule(),
            FailedLoginRule(),
            SuspiciousNetworkConnectionRule()
        ]
        
    def scan(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        for event in events:
            for rule in self.rules:
                rule.evaluate(event)
        return events
