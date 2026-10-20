import uuid
from typing import List

from core.normalization import NormalizationEngine as N
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser

WINDOWS_EVENT_NAMES = {
    "4624": "Successful logon", "4625": "Failed logon", "4634": "Logoff",
    "4648": "Logon with explicit credentials", "4672": "Special privileges assigned",
    "4688": "Process created", "4698": "Scheduled task created", "4720": "User account created",
    "4728": "Member added to global group", "4732": "Member added to local group",
    "4756": "Member added to universal group", "7045": "Service installed",
    "1102": "Security log cleared", "4697": "Service installed",
}


class WindowsEventParser(BaseParser):
    SOURCE_NAME = "Windows Event Log"
    COLUMN_ALIASES = {
        "TimeCreated": ("Date and Time", "TimeGenerated", "Timestamp", "@timestamp", "UtcTime"),
        "EventID": ("Event ID", "Id", "EventCode"),
        "Computer": ("MachineName", "Hostname", "Host"),
        "IpAddress": ("Source Network Address", "SourceIp", "ClientAddress"),
        "Message": ("Description",),
    }
    REQUIRED_COLUMNS = (("TimeCreated",), ("EventID",))

    def parse(self, file_path: str) -> List[NormalizedEvent]:
        df = self._load(file_path)
        if df is None:
            return []
        return self._iter_rows(df, file_path, "TimeCreated", self._build)

    @staticmethod
    def _build(r: dict, ts) -> NormalizedEvent:
        eid = r.get("EventID") or "Unknown"
        if eid in ("4732", "4728", "4756"):
            user = r.get("MemberName") or r.get("TargetUserName")
        else:
            user = r.get("TargetUserName") or r.get("SubjectUserName")
        image = r.get("NewProcessName") or r.get("ImagePath") or r.get("ServiceFileName")
        event = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source="Windows Event Log",
            event_type=eid,
            host=r.get("Computer"),
            username=user,
            process_name=image,
            process_id=N.to_int(r.get("NewProcessId")),
            parent_process=r.get("ParentProcessName"),
            parent_process_id=N.to_int(r.get("ProcessId")) if eid == "4688" else None,
            command_line=r.get("CommandLine") or r.get("ImagePath") or r.get("TaskContent"),
            source_ip=N.normalize_ip(r.get("IpAddress")),
            source_port=N.to_int(r.get("IpPort")),
            logon_type=r.get("LogonType"),
        )
        name = WINDOWS_EVENT_NAMES.get(eid, f"Windows event {eid}")
        event.description = r.get("Message") or f"{name}" + (f" ({user})" if user else "")
        return event
