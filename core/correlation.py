from typing import List
from models.event_model import NormalizedEvent

class CorrelationEngine:
    def correlate(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        # Sort by timestamp to reconstruct timeline
        events.sort(key=lambda x: x.timestamp)
        return events
