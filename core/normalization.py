import pandas as pd
from typing import Any
from datetime import datetime

class NormalizationEngine:
    @staticmethod
    def parse_timestamp(ts: Any) -> datetime:
        if pd.isna(ts) or not ts:
            return datetime.min
        try:
            return pd.to_datetime(ts).to_pydatetime()
        except Exception:
            return datetime.min
