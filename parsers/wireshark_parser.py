import re
import uuid
from typing import List

from core.normalization import NormalizationEngine as N
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser

_PORTS_RE = re.compile(r"\b(\d{1,5})\s*(?:→|->|>)\s*(\d{1,5})\b")
_DNS_RE = re.compile(r"(?:Standard query(?: response)?\s+0x[0-9a-f]+\s+\w+\s+)([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
                     re.IGNORECASE)


class WiresharkParser(BaseParser):
    SOURCE_NAME = "Wireshark"
    COLUMN_ALIASES = {
        "Time": ("frame.time", "Timestamp", "Absolute Time", "frame.time_epoch", "Date"),
        "Source": ("ip.src", "Src", "Source Address", "SourceIp"),
        "Destination": ("ip.dst", "Dst", "Destination Address", "DestinationIp"),
        "SrcPort": ("Source Port", "tcp.srcport", "udp.srcport", "srcport"),
        "DstPort": ("Destination Port", "tcp.dstport", "udp.dstport", "dstport"),
        "Length": ("frame.len", "Len"),
    }
    REQUIRED_COLUMNS = (("Time",), ("Source",), ("Destination",))

    def parse(self, file_path: str) -> List[NormalizedEvent]:
        df = self._load(file_path)
        if df is None:
            return []
        return self._iter_rows(df, file_path, "Time", self._build)

    @staticmethod
    def _build(r: dict, ts) -> NormalizedEvent:
        info = r.get("Info") or ""
        sport, dport = N.to_int(r.get("SrcPort")), N.to_int(r.get("DstPort"))
        if sport is None or dport is None:
            m = _PORTS_RE.search(info)
            if m:
                sport, dport = sport or int(m.group(1)), dport or int(m.group(2))
        dns = _DNS_RE.search(info)
        size = N.to_int(r.get("Bytes")) or N.to_int(r.get("Length"))
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source="Wireshark",
            event_type="Network Traffic",
            source_ip=N.normalize_ip(r.get("Source")) or r.get("Source"),
            destination_ip=N.normalize_ip(r.get("Destination")) or r.get("Destination"),
            source_port=sport,
            destination_port=dport,
            protocol=r.get("Protocol"),
            domain=dns.group(1).lower() if dns else None,
            bytes_transferred=size,
            description=info,
        )
