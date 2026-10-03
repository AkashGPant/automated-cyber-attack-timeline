import pandas as pd
import uuid
from typing import List
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser
from core.normalization import NormalizationEngine

class WiresharkParser(BaseParser):
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        try:
            df = pd.read_csv(file_path)
        except Exception:
            return []
            
        events = []
        for _, row in df.iterrows():
            event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=NormalizationEngine.parse_timestamp(row.get('Time')),
                source='Wireshark',
                event_type='Network Traffic',
                source_ip=str(row.get('Source', '')),
                destination_ip=str(row.get('Destination', '')),
                protocol=str(row.get('Protocol', '')),
                description=str(row.get('Info', '')),
                raw_data=row.to_dict()
            )
            events.append(event)
        return events
