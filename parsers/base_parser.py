from __future__ import annotations

import logging
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Sequence

import pandas as pd

from config.config import MAX_UPLOAD_ROWS
from core.normalization import NormalizationEngine
from models.event_model import NormalizedEvent

logger = logging.getLogger(__name__)

_ENCODINGS = ("utf-8-sig", "utf-16", "latin-1")


def _canon(name: str) -> str:
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def read_csv_robust(file_path: str, nrows: Optional[int] = None,
                    bad_lines: Optional[list] = None) -> pd.DataFrame:
    """Read a CSV as strings, trying several encodings and tolerating bad lines."""
    last_exc: Optional[Exception] = None
    for enc in _ENCODINGS:
        try:
            return pd.read_csv(file_path, dtype=str, encoding=enc, nrows=nrows,
                               keep_default_na=True, skipinitialspace=True)
        except UnicodeError as exc:
            last_exc = exc
            continue
        except pd.errors.ParserError:
            collected = bad_lines if bad_lines is not None else []
            return pd.read_csv(file_path, dtype=str, encoding=enc, nrows=nrows,
                               engine="python",
                               on_bad_lines=lambda line: collected.append(line) and None)
    raise ValueError(f"Unable to decode file with encodings {_ENCODINGS}: {last_exc}")


class BaseParser(ABC):
    """Common CSV loading, column aliasing and validation for all parsers."""

    SOURCE_NAME = "Unknown"
    # Canonical column -> accepted aliases (compared case/punctuation-insensitively)
    COLUMN_ALIASES: Dict[str, Sequence[str]] = {}
    # Each inner tuple is an any-of group; all groups must be satisfied.
    REQUIRED_COLUMNS: Sequence[Sequence[str]] = ()

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.rows_read = 0
        self.rows_skipped = 0

    @abstractmethod
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        pass

    # ------------------------------------------------------------------ helpers
    def _load(self, file_path: str) -> Optional[pd.DataFrame]:
        self.errors, self.warnings = [], []
        self.rows_read = self.rows_skipped = 0
        name = os.path.basename(file_path)
        if not os.path.isfile(file_path):
            self.errors.append(f"{name}: file not found")
            return None
        if os.path.getsize(file_path) == 0:
            self.errors.append(f"{name}: file is empty")
            return None
        bad_lines: list = []
        try:
            df = read_csv_robust(file_path, bad_lines=bad_lines)
        except (ValueError, OSError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
            self.errors.append(f"{name}: unreadable CSV ({exc})")
            return None
        if bad_lines:
            self.warnings.append(f"{name}: skipped {len(bad_lines)} malformed line(s)")
        df = self._apply_aliases(df)
        missing = [" | ".join(group) for group in self.REQUIRED_COLUMNS
                   if not any(col in df.columns for col in group)]
        if missing:
            self.errors.append(f"{name}: missing required column(s) for {self.SOURCE_NAME}: "
                               + ", ".join(missing))
            return None
        if df.empty:
            self.warnings.append(f"{name}: no data rows")
        if len(df) > MAX_UPLOAD_ROWS:
            self.warnings.append(f"{name}: truncated to {MAX_UPLOAD_ROWS} rows")
            df = df.head(MAX_UPLOAD_ROWS)
        self.rows_read = len(df)
        return df

    def _apply_aliases(self, df: pd.DataFrame) -> pd.DataFrame:
        df.columns = [str(c).strip().lstrip("﻿") for c in df.columns]
        lookup = {_canon(c): c for c in df.columns}
        rename = {}
        for canonical, aliases in self.COLUMN_ALIASES.items():
            if canonical in df.columns:
                continue
            for alias in (canonical, *aliases):
                actual = lookup.get(_canon(alias))
                if actual is not None and actual not in rename:
                    rename[actual] = canonical
                    break
        return df.rename(columns=rename)

    def _iter_rows(self, df: pd.DataFrame, file_path: str, ts_column: str, builder) -> List[NormalizedEvent]:
        """Run ``builder(row_dict, timestamp)`` per row with per-row error isolation."""
        name = os.path.basename(file_path)
        events: List[NormalizedEvent] = []
        bad_ts = 0
        failed = 0
        for idx, row in enumerate(df.to_dict(orient="records"), start=2):  # header is line 1
            clean = {k: NormalizationEngine.clean_str(v) for k, v in row.items()}
            ts = NormalizationEngine.parse_timestamp(clean.get(ts_column))
            if ts == datetime.min:
                bad_ts += 1
                continue
            try:
                event = builder(clean, ts)
            except Exception as exc:  # keep processing remaining evidence
                failed += 1
                logger.debug("Row %s of %s failed: %s", idx, name, exc)
                continue
            event.event_id = event.event_id or str(uuid.uuid4())
            event.source_file = name
            event.row_number = idx
            event.raw_data = {k: v for k, v in clean.items() if v is not None}
            events.append(event)
        if bad_ts:
            self.warnings.append(f"{name}: skipped {bad_ts} row(s) with missing/invalid "
                                 f"timestamp in '{ts_column}' (relative times are not supported)")
        if failed:
            self.warnings.append(f"{name}: skipped {failed} row(s) that could not be parsed")
        self.rows_skipped = bad_ts + failed
        return events
