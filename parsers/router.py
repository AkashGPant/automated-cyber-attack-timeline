"""Pick the right parser for a CSV from its header (filename is only a fallback)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser, _canon, read_csv_robust
from parsers.sysmon_parser import SysmonParser
from parsers.windows_event_parser import WindowsEventParser
from parsers.wireshark_parser import WiresharkParser


@dataclass
class ParseReport:
    file: str
    parser: Optional[str]
    events: int = 0
    rows_read: int = 0
    rows_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def detect_parser(file_path: str) -> Optional[BaseParser]:
    try:
        header = read_csv_robust(file_path, nrows=0)
        cols = {_canon(c) for c in header.columns}
    except Exception:
        cols = set()
    sysmon_markers = {"utctime", "image", "parentimage", "processguid", "hashes", "targetfilename"}
    windows_markers = {"timecreated", "targetusername", "subjectusername", "logontype",
                       "newprocessname", "dateandtime", "taskcategory"}
    network_markers = {"source", "destination", "info", "protocol", "ipsrc", "ipdst"}
    scores = {
        "sysmon": len(cols & sysmon_markers),
        "windows": len(cols & windows_markers),
        "network": len(cols & network_markers) if {"source", "destination"} <= cols
        or {"ipsrc", "ipdst"} <= cols else 0,
    }
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        lower = os.path.basename(file_path).lower()
        if "sysmon" in lower:
            best = "sysmon"
        elif "network" in lower or "pcap" in lower or "wireshark" in lower:
            best = "network"
        elif "windows" in lower or "security" in lower:
            best = "windows"
        else:
            return None
    return {"sysmon": SysmonParser, "windows": WindowsEventParser,
            "network": WiresharkParser}[best]()


def parse_file(file_path: str) -> Tuple[List[NormalizedEvent], ParseReport]:
    name = os.path.basename(file_path)
    parser = detect_parser(file_path)
    if parser is None:
        return [], ParseReport(file=name, parser=None,
                               errors=[f"{name}: unrecognised log format (expected Windows "
                                       "Event Log, Sysmon or Wireshark CSV export)"])
    events = parser.parse(file_path)
    return events, ParseReport(file=name, parser=parser.SOURCE_NAME, events=len(events),
                               rows_read=parser.rows_read, rows_skipped=parser.rows_skipped,
                               errors=list(parser.errors), warnings=list(parser.warnings))
