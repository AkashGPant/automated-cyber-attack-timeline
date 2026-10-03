import pandas as pd
import json
import os
from typing import List
from models.event_model import NormalizedEvent
from config.config import REPORTS_DIR

class ReportGenerator:
    def generate_csv(self, events: List[NormalizedEvent], filename="forensic_report.csv") -> str:
        df = pd.DataFrame([e.to_dict() for e in events])
        path = os.path.join(REPORTS_DIR, filename)
        df.to_csv(path, index=False)
        return path
        
    def generate_json(self, events: List[NormalizedEvent], filename="forensic_report.json") -> str:
        data = [e.to_dict() for e in events]
        path = os.path.join(REPORTS_DIR, filename)
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
        return path
