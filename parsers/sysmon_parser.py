import uuid
from typing import List

from core.normalization import NormalizationEngine as N
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser

SYSMON_EVENT_NAMES = {
    "1": "Process created", "3": "Network connection", "5": "Process terminated",
    "7": "Image loaded", "8": "CreateRemoteThread", "10": "Process accessed",
    "11": "File created", "12": "Registry object created/deleted", "13": "Registry value set",
    "15": "File stream created", "22": "DNS query", "23": "File deleted",
}


class SysmonParser(BaseParser):
    SOURCE_NAME = "Sysmon"
    COLUMN_ALIASES = {
        "UtcTime": ("TimeCreated", "Timestamp", "@timestamp", "Date and Time"),
        "EventID": ("Event ID", "Id", "EventCode"),
        "Computer": ("Hostname", "Host", "MachineName"),
        "User": ("UserName",),
        "Image": ("ProcessName",),
        "ProcessId": ("PID",),
        "ParentProcessId": ("PPID",),
    }
    REQUIRED_COLUMNS = (("UtcTime",), ("EventID",))

    def parse(self, file_path: str) -> List[NormalizedEvent]:
        df = self._load(file_path)
        if df is None:
            return []
        return self._iter_rows(df, file_path, "UtcTime", self._build)

    @staticmethod
    def _build(r: dict, ts) -> NormalizedEvent:
        eid = r.get("EventID") or "Unknown"
        image = r.get("Image")
        if eid == "10":
            image = r.get("SourceImage") or image
        event = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source="Sysmon",
            event_type=eid,
            host=r.get("Computer"),
            username=r.get("User"),
            process_name=image,
            process_id=N.to_int(r.get("ProcessId") or r.get("SourceProcessId")),
            parent_process=r.get("ParentImage"),
            parent_process_id=N.to_int(r.get("ParentProcessId")),
            command_line=r.get("CommandLine"),
            source_ip=N.normalize_ip(r.get("SourceIp")),
            destination_ip=N.normalize_ip(r.get("DestinationIp")),
            source_port=N.to_int(r.get("SourcePort")),
            destination_port=N.to_int(r.get("DestinationPort")),
            protocol=r.get("Protocol"),
            file_path=r.get("TargetFilename"),
            domain=r.get("QueryName") or r.get("DestinationHostname"),
            registry_key=r.get("TargetObject"),
            hashes=N.parse_hashes(r.get("Hashes")),
        )
        name = SYSMON_EVENT_NAMES.get(eid, f"Sysmon event {eid}")
        detail = (event.command_line or event.file_path or event.registry_key or event.domain
                  or (f"{event.destination_ip}:{event.destination_port}" if event.destination_ip else None)
                  or image or "")
        event.description = r.get("Message") or f"{name}: {detail}".strip(": ")
        return event
