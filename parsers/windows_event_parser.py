import pandas as pd
import uuid
from typing import List
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser
from core.normalization import NormalizationEngine

class WindowsEventParser(BaseParser):
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        try:
            df = pd.read_csv(file_path)
        except Exception:
            return []
            
        events = []
        for _, row in df.iterrows():
            event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=NormalizationEngine.parse_timestamp(row.get('TimeCreated')),
                source='Windows Event Log',
                event_type=str(row.get('EventID', 'Unknown')),
                host=str(row.get('Computer', '')),
                username=str(row.get('TargetUserName', row.get('SubjectUserName', ''))),
                process_name=str(row.get('NewProcessName', '')),
                parent_process=str(row.get('ParentProcessName', '')),
                command_line=str(row.get('CommandLine', '')),
                description=str(row.get('Message', '')),
                raw_data=row.to_dict()
            )
            events.append(event)
        return events
