import pandas as pd
import uuid
from typing import List
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser
from core.normalization import NormalizationEngine

class SysmonParser(BaseParser):
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        try:
            df = pd.read_csv(file_path)
        except Exception:
            return []
            
        events = []
        for _, row in df.iterrows():
            event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=NormalizationEngine.parse_timestamp(row.get('UtcTime')),
                source='Sysmon',
                event_type=str(row.get('EventID', 'Unknown')),
                host=str(row.get('Computer', '')),
                username=str(row.get('User', '')),
                process_name=str(row.get('Image', '')),
                parent_process=str(row.get('ParentImage', '')),
                command_line=str(row.get('CommandLine', '')),
                source_ip=str(row.get('SourceIp', '')),
                destination_ip=str(row.get('DestinationIp', '')),
                protocol=str(row.get('Protocol', '')),
                file_path=str(row.get('TargetFilename', '')),
                raw_data=row.to_dict()
            )
            events.append(event)
        return events
