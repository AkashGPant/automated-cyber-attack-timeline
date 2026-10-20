"""Detection rules.

Event rules implement ``evaluate(event) -> list[Detection]``; behavioural rules
implement ``evaluate_all(events, context) -> list[Detection]``. Rules never
modify risk scores directly; scoring is done by ``core.risk_scoring``.
"""
from __future__ import annotations

import ntpath
import re
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence

from config.detection_config import DEFAULT_RULE_CONFIG
from core.normalization import NormalizationEngine, ip_in_networks, is_external_ip
from detection.mitre_mapping import technique
from models.detection_model import Detection
from models.event_model import NormalizedEvent


# --------------------------------------------------------------------------- helpers
def basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return ntpath.basename(str(path).strip().strip('"')).lower()


def is_process_creation(e: NormalizedEvent) -> bool:
    return (e.source == "Sysmon" and e.event_type == "1") or \
           (e.source == "Windows Event Log" and e.event_type == "4688")


def image_of(e: NormalizedEvent) -> str:
    name = basename(e.process_name)
    if not name and e.command_line:
        first = e.command_line.strip().split()[0] if e.command_line.strip() else ""
        name = basename(first)
    return name


def make_detection(rule: "DetectionRule", events: Sequence[NormalizedEvent], technique_id: str,
                   severity: str, confidence: float, description: str,
                   evidence: Iterable[str], tactic: Optional[str] = None,
                   entities: Optional[Dict[str, Any]] = None) -> Detection:
    tech = technique(technique_id)
    events = sorted(events, key=lambda x: x.timestamp)
    first = events[0]
    return Detection(
        detection_id=f"DET-{uuid.uuid4().hex[:10].upper()}",
        rule_id=rule.rule_id,
        rule_name=rule.name,
        technique_id=technique_id,
        technique_name=tech["name"],
        tactic=tactic or tech["tactics"][0],
        severity=severity,
        confidence=round(max(0.05, min(confidence, 0.99)), 2),
        timestamp=first.timestamp,
        end_time=events[-1].timestamp if len(events) > 1 else None,
        description=description,
        host=first.host,
        user=first.username,
        event_ids=[e.event_id for e in events],
        evidence=[s for s in evidence if s],
        evidence_refs=[e.evidence_ref for e in events][:50],
        entities=entities or {},
    )


class DetectionRule:
    rule_id = "BASE"
    name = "Base rule"
    config_key = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or DEFAULT_RULE_CONFIG
        self.g = cfg.get("global", DEFAULT_RULE_CONFIG["global"])
        self.cfg = cfg.get(self.config_key, DEFAULT_RULE_CONFIG.get(self.config_key, {}))

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True))

    def evaluate(self, event: NormalizedEvent) -> List[Detection]:
        return []

    # shared predicates
    def user_writable(self, path: Optional[str]) -> bool:
        p = str(path or "").lower()
        return any(marker in p for marker in self.g["user_writable_paths"])

    def trusted_process(self, path: Optional[str]) -> bool:
        p = str(path or "").lower().strip('"')
        return any(p.startswith(prefix) for prefix in self.g["trusted_process_prefixes"])

    def external(self, ip: Optional[str]) -> bool:
        return is_external_ip(ip, self.g["internal_cidrs"])

    def allowlisted_dest(self, ip: Optional[str], domain: Optional[str] = None) -> bool:
        if ip_in_networks(ip, self.g["allowlisted_cidrs"]):
            return True
        d = (domain or "").lower().rstrip(".")
        return any(d == a or d.endswith("." + a) for a in self.g["allowlisted_domains"])

    def watchlisted(self, ip: Optional[str], domain: Optional[str] = None) -> bool:
        d = (domain or "").lower()
        return (ip in self.g.get("watchlist_ips", [])) or \
            any(d == w or d.endswith("." + w) for w in self.g.get("watchlist_domains", []))


class AggregateRule(DetectionRule):
    def evaluate_all(self, events: List[NormalizedEvent], context: Dict[str, Any]) -> List[Detection]:
        return []


# --------------------------------------------------------------------------- event rules
class SuspiciousPowerShellRule(DetectionRule):
    rule_id = "CIA-EXE-001"
    name = "Suspicious PowerShell execution"
    config_key = "suspicious_powershell"

    STRONG = {
        "encoded command": r"\s-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{16,}",
        "hidden window": r"-w(?:indowstyle)?\s+h(?:idden)?\b",
        "download cradle": r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|"
                           r"net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b",
        "in-memory execution (IEX)": r"\biex\b|invoke-expression",
        "base64 decoding": r"frombase64string",
        "AMSI tampering": r"amsiutils|amsiinitfailed|amsicontext",
        "reflective loading": r"reflection\.assembly|::load\(",
    }
    WEAK = {
        "execution policy bypass": r"-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)",
        "no profile": r"\s-nop(?:rofile)?\b",
        "non-interactive": r"\s-noni(?:nteractive)?\b",
    }

    def evaluate(self, event):
        if not (is_process_creation(event) and event.command_line):
            return []
        img = image_of(event)
        cmd = event.command_line
        if img not in ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and \
                "powershell" not in cmd.lower()[:120]:
            return []
        decoded = NormalizationEngine.decode_powershell(cmd)
        haystack = (cmd + " " + (decoded or "")).lower()
        strong = [k for k, rx in self.STRONG.items() if re.search(rx, haystack, re.I)]
        weak = [k for k, rx in self.WEAK.items() if re.search(rx, haystack, re.I)]
        if len(strong) < max(1, int(self.cfg.get("min_indicators", 1))):
            return []
        sev = "HIGH" if len(strong) >= 2 else "MEDIUM"
        conf = 0.5 + 0.12 * len(strong) + 0.04 * len(weak)
        evidence = [f"Indicators: {', '.join(strong + weak)}", f"Command line: {cmd[:300]}"]
        if decoded:
            evidence.append(f"Decoded payload: {decoded[:300]}")
        if event.parent_process:
            evidence.append(f"Parent: {event.parent_process}")
        return [make_detection(self, [event], "T1059.001", sev, conf,
                               f"Suspicious PowerShell on {event.host} ({', '.join(strong)})",
                               evidence, entities={"process": event.process_name,
                                                   "pid": event.process_id,
                                                   "decoded": decoded})]


class LolbinRule(DetectionRule):
    rule_id = "CIA-DEF-001"
    name = "Living-off-the-land binary abuse"
    config_key = "lolbins"

    # (binary, regex on command line, technique, severity, confidence, label)
    PATTERNS = [
        ("certutil.exe", r"-urlcache|-verifyctl|https?://", "T1105", "HIGH", 0.9, "certutil download"),
        ("certutil.exe", r"-decode(?:hex)?\b", "T1140", "MEDIUM", 0.75, "certutil decode"),
        ("mshta.exe", r"https?://|javascript:|vbscript:", "T1218.005", "HIGH", 0.9, "mshta remote/script execution"),
        ("rundll32.exe", r"javascript:|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|"
                         r"url\.dll,\s*(?:openurl|fileprotocolhandler)", "T1218.011", "HIGH", 0.8,
         "rundll32 proxy execution"),
        ("regsvr32.exe", r"/i:\s*https?://|scrobj\.dll", "T1218.010", "HIGH", 0.9, "regsvr32 Squiblydoo"),
        ("bitsadmin.exe", r"/transfer|/addfile|/setnotifycmdline", "T1197", "MEDIUM", 0.8, "bitsadmin transfer"),
        ("wmic.exe", r"process\s+call\s+create", "T1047", "MEDIUM", 0.7, "WMIC process creation"),
        ("msiexec.exe", r"https?://", "T1218.007", "HIGH", 0.8, "msiexec remote package"),
        ("installutil.exe", r"/logtoconsole=false|/u\s", "T1218.004", "HIGH", 0.75, "InstallUtil proxy execution"),
        ("msbuild.exe", r"\\appdata\\|\\temp\\|\\users\\public\\", "T1127.001", "MEDIUM", 0.7,
         "MSBuild inline task from user-writable path"),
    ]

    def evaluate(self, event):
        if not (is_process_creation(event) and event.command_line):
            return []
        img = image_of(event)
        out = []
        for binary, rx, tid, sev, conf, label in self.PATTERNS:
            if img == binary and re.search(rx, event.command_line, re.I):
                if binary == "wmic.exe" and "/node:" in event.command_line.lower():
                    sev, conf = "HIGH", 0.85
                out.append(make_detection(
                    self, [event], tid, sev, conf, f"{label} on {event.host}",
                    [f"Binary: {event.process_name}", f"Command line: {event.command_line[:300]}",
                     f"Parent: {event.parent_process}" if event.parent_process else ""],
                    entities={"process": event.process_name, "pid": event.process_id}))
                break
        return out


class PersistenceRule(DetectionRule):
    rule_id = "CIA-PER-001"
    name = "Persistence mechanism"
    config_key = "persistence"

    RUN_KEY = re.compile(r"\\currentversion\\(?:run|runonce|runservices)\b|\\winlogon\\(?:shell|userinit)\b|"
                         r"\\explorer\\(?:user )?shell folders\\startup", re.I)
    SCRIPT_HOSTS = re.compile(r"powershell|pwsh|cmd(?:\.exe)?\s+/c|mshta|wscript|cscript|rundll32|regsvr32|"
                              r"%comspec%|\.ps1|\.vbs|\.js\b|\.hta", re.I)

    def _suspicious_target(self, text: Optional[str]) -> bool:
        return bool(text) and (self.user_writable(text) or bool(self.SCRIPT_HOSTS.search(text)))

    def evaluate(self, e):
        cmd = e.command_line or ""
        low = cmd.lower()
        raw = e.raw_data
        # Registry run keys
        if e.source == "Sysmon" and e.event_type in ("12", "13") and e.registry_key and \
                self.RUN_KEY.search(e.registry_key):
            details = raw.get("Details", "")
            if self.trusted_process(e.process_name) and not self._suspicious_target(details):
                return []
            sev, conf = ("HIGH", 0.9) if self._suspicious_target(details) else ("MEDIUM", 0.6)
            return [make_detection(self, [e], "T1547.001", sev, conf,
                                   f"Autorun registry value set on {e.host}",
                                   [f"Key: {e.registry_key}", f"Value: {details}", f"Writer: {e.process_name}"],
                                   entities={"registry_key": e.registry_key, "value": details})]
        if is_process_creation(e) and re.search(r"\breg(?:\.exe)?\s+add\b", low) and self.RUN_KEY.search(low):
            sev, conf = ("HIGH", 0.85) if self._suspicious_target(cmd) else ("MEDIUM", 0.6)
            return [make_detection(self, [e], "T1547.001", sev, conf, f"Run key added via reg.exe on {e.host}",
                                   [f"Command line: {cmd[:300]}"])]
        # Startup folder drop
        if e.source == "Sysmon" and e.event_type == "11" and e.file_path and \
                "\\start menu\\programs\\startup\\" in e.file_path.lower():
            return [make_detection(self, [e], "T1547.001", "HIGH", 0.85, f"File dropped in Startup folder on {e.host}",
                                   [f"File: {e.file_path}", f"Writer: {e.process_name}"])]
        # Service installation
        if e.source == "Windows Event Log" and e.event_type in ("7045", "4697"):
            path = raw.get("ImagePath") or raw.get("ServiceFileName") or e.process_name or ""
            if not self._suspicious_target(path):
                return []
            return [make_detection(self, [e], "T1543.003", "HIGH", 0.9,
                                   f"Suspicious service installed on {e.host}",
                                   [f"Service: {raw.get('ServiceName', '?')}", f"Image path: {path}"],
                                   entities={"service": raw.get("ServiceName")})]
        if is_process_creation(e) and re.search(r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b", low):
            if not self._suspicious_target(cmd.split("create", 1)[-1]):
                return []
            return [make_detection(self, [e], "T1543.003", "HIGH", 0.85, f"Service created via sc.exe on {e.host}",
                                   [f"Command line: {cmd[:300]}"])]
        # Scheduled tasks
        if (e.source == "Windows Event Log" and e.event_type == "4698") or \
                (is_process_creation(e) and re.search(r"schtasks(?:\.exe)?\s+.*?/create", low)):
            target = raw.get("TaskContent") or cmd
            if self.trusted_process(e.parent_process) and not self._suspicious_target(target):
                return []
            if not self._suspicious_target(target):
                sev, conf = "LOW", 0.4
            else:
                sev, conf = "HIGH", 0.85
                if re.search(r"/ru\s+\"?system", low):
                    conf = 0.9
            return [make_detection(self, [e], "T1053.005", sev, conf, f"Scheduled task created on {e.host}",
                                   [f"Task: {raw.get('TaskName', '')}", f"Action: {target[:300]}"])]
        # Account creation
        if e.source == "Windows Event Log" and e.event_type == "4720":
            return [make_detection(self, [e], "T1136.001", "MEDIUM", 0.7, f"Local account created on {e.host}",
                                   [f"New account: {e.username}", f"Created by: {raw.get('SubjectUserName', '?')}"])]
        if is_process_creation(e) and re.search(r"\bnet1?(?:\.exe)?\s+user\s+\S+\s+\S*\s*/add", low):
            return [make_detection(self, [e], "T1136.001", "MEDIUM", 0.75, f"Account created via net.exe on {e.host}",
                                   [f"Command line: {cmd[:300]}"])]
        return []


class PrivilegeEscalationRule(DetectionRule):
    rule_id = "CIA-PRV-001"
    name = "Privilege escalation"
    config_key = "privilege_escalation"

    ADMIN_GROUPS = re.compile(r"^(administrators|domain admins|enterprise admins|schema admins|"
                              r"backup operators|account operators)$", re.I)
    UAC_KEYS = re.compile(r"\\(?:ms-settings|mscfile|exefile|folder)\\shell\\open\\command", re.I)
    UAC_BINARIES = {"fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe", "slui.exe"}

    def evaluate(self, e):
        raw, low = e.raw_data, (e.command_line or "").lower()
        if e.source == "Windows Event Log" and e.event_type in ("4732", "4728", "4756"):
            group = raw.get("TargetUserName") or raw.get("GroupName") or ""
            if not self.ADMIN_GROUPS.match(group.strip()):
                return []
            return [make_detection(self, [e], "T1098", "HIGH", 0.85,
                                   f"Account added to privileged group '{group}' on {e.host}",
                                   [f"Member: {e.username}", f"Group: {group}",
                                    f"Changed by: {raw.get('SubjectUserName', '?')}"],
                                   tactic="Privilege Escalation")]
        if is_process_creation(e) and (
                re.search(r"\bnet1?(?:\.exe)?\s+(?:localgroup|group)\s+\"?(?:administrators|domain admins)\"?\s+\S+.*/add", low)
                or re.search(r"add-localgroupmember\s+.*administrators", low)):
            return [make_detection(self, [e], "T1098", "HIGH", 0.85,
                                   f"User added to administrators via command line on {e.host}",
                                   [f"Command line: {e.command_line[:300]}"], tactic="Privilege Escalation")]
        if e.source == "Sysmon" and e.event_type in ("12", "13") and e.registry_key and \
                self.UAC_KEYS.search(e.registry_key):
            return [make_detection(self, [e], "T1548.002", "HIGH", 0.9, f"UAC bypass registry hijack on {e.host}",
                                   [f"Key: {e.registry_key}", f"Value: {raw.get('Details', '')}"])]
        if is_process_creation(e) and basename(e.parent_process) in self.UAC_BINARIES and \
                image_of(e) not in ("werfault.exe", "consent.exe", "mmc.exe"):
            return [make_detection(self, [e], "T1548.002", "HIGH", 0.8,
                                   f"Auto-elevated binary spawned {image_of(e)} on {e.host}",
                                   [f"Parent: {e.parent_process}", f"Child: {e.command_line or e.process_name}"])]
        return []


class CredentialAccessRule(DetectionRule):
    rule_id = "CIA-CRD-001"
    name = "Credential dumping"
    config_key = "credential_access"
    CMD = re.compile(r"comsvcs(?:\.dll)?[, ]+#?(?:minidump|24)|procdump.*lsass|sekurlsa|mimikatz|"
                     r"lsadump::|out-minidump", re.I)
    ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x40"}
    BENIGN_SOURCES = {"msmpeng.exe", "csrss.exe", "wininit.exe", "lsm.exe", "svchost.exe",
                      "mrt.exe", "wmiprvse.exe", "taskmgr.exe"}

    def evaluate(self, e):
        if is_process_creation(e) and e.command_line and self.CMD.search(e.command_line):
            return [make_detection(self, [e], "T1003.001", "CRITICAL", 0.9, f"LSASS credential dumping on {e.host}",
                                   [f"Command line: {e.command_line[:300]}"])]
        if e.source == "Sysmon" and e.event_type == "10" and basename(e.raw_data.get("TargetImage")) == "lsass.exe":
            access = str(e.raw_data.get("GrantedAccess", "")).lower()
            if access in self.ACCESS and basename(e.process_name) not in self.BENIGN_SOURCES:
                return [make_detection(self, [e], "T1003.001", "CRITICAL", 0.85,
                                       f"Suspicious LSASS memory access on {e.host}",
                                       [f"Source: {e.process_name}", f"GrantedAccess: {access}"])]
        return []


class DefenseEvasionRule(DetectionRule):
    rule_id = "CIA-DEF-002"
    name = "Defense evasion / anti-forensics"
    config_key = "defense_evasion"

    def evaluate(self, e):
        low = (e.command_line or "").lower()
        if (e.source == "Windows Event Log" and e.event_type in ("1102", "104")) or \
                (is_process_creation(e) and re.search(r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog", low)):
            return [make_detection(self, [e], "T1070.001", "HIGH", 0.9, f"Event log cleared on {e.host}",
                                   [f"Event {e.event_type}: {e.description or e.command_line}"])]
        if is_process_creation(e) and re.search(r"set-mppreference.*-disable\w*\s+(?:\$?true|1)|"
                                                r"disablerealtimemonitoring|add-mppreference\s+-exclusionpath", low):
            return [make_detection(self, [e], "T1562.001", "HIGH", 0.85, f"Defender tampering on {e.host}",
                                   [f"Command line: {e.command_line[:300]}"])]
        if is_process_creation(e) and re.search(r"vssadmin(?:\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|"
                                                r"bcdedit.*recoveryenabled\s+no|wbadmin\s+delete\s+catalog", low):
            return [make_detection(self, [e], "T1490", "CRITICAL", 0.9, f"Recovery inhibition on {e.host}",
                                   [f"Command line: {e.command_line[:300]}"])]
        return []


class OfficeChildProcessRule(DetectionRule):
    rule_id = "CIA-EXE-002"
    name = "Office application spawned interpreter"
    config_key = "office_child_process"
    OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe"}
    CHILD = {"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe",
             "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}

    def evaluate(self, e):
        if is_process_creation(e) and basename(e.parent_process) in self.OFFICE and image_of(e) in self.CHILD:
            return [make_detection(self, [e], "T1204.002", "HIGH", 0.85,
                                   f"{basename(e.parent_process)} spawned {image_of(e)} on {e.host}",
                                   [f"Parent: {e.parent_process}", f"Child command: {(e.command_line or '')[:300]}"])]
        return []


class IngressToolTransferRule(DetectionRule):
    rule_id = "CIA-C2-002"
    name = "Payload dropped by script/LOLBin"
    config_key = "ingress_tool_transfer"
    WRITERS = {"powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "curl.exe",
               "wget.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe"}

    def evaluate(self, e):
        if not (e.source == "Sysmon" and e.event_type == "11" and e.file_path):
            return []
        exts = tuple(self.cfg.get("extensions", []))
        if basename(e.process_name) in self.WRITERS and e.file_path.lower().endswith(exts) \
                and self.user_writable(e.file_path):
            return [make_detection(self, [e], "T1105", "HIGH", 0.8,
                                   f"{basename(e.process_name)} wrote executable content on {e.host}",
                                   [f"File: {e.file_path}", f"Writer: {e.process_name}"],
                                   entities={"file": e.file_path})]
        return []


class SuspiciousNetworkConnectionRule(DetectionRule):
    rule_id = "CIA-C2-001"
    name = "Suspicious outbound connection"
    config_key = "suspicious_network_connection"
    NET_LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "powershell.exe",
                   "pwsh.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe"}
    EXFIL_CMD = [
        (re.compile(r"\brclone(?:\.exe)?\s+(?:copy|sync|move)\b", re.I), "T1567.002", "HIGH", 0.85,
         "rclone upload to cloud storage"),
        (re.compile(r"\bcurl(?:\.exe)?\s+.*(?:-T\s|--upload-file|-F\s+\S*@|--data-binary\s+@)", re.I), "T1048",
         "MEDIUM", 0.6, "curl file upload"),
        (re.compile(r"\b(?:7z|7za|rar|winrar)(?:\.exe)?\s+a\b.*\s-(?:p|hp)\S+", re.I), "T1560.001", "MEDIUM", 0.7,
         "password-protected archive created"),
    ]

    def __init__(self, config=None):
        super().__init__(config)
        self._seen: Dict[tuple, Detection] = {}

    def reset(self):
        self._seen = {}

    def evaluate(self, e):
        if is_process_creation(e) and e.command_line:
            for rx, tid, sev, conf, label in self.EXFIL_CMD:
                if rx.search(e.command_line):
                    return [make_detection(self, [e], tid, sev, conf, f"{label} on {e.host}",
                                           [f"Command line: {e.command_line[:300]}"])]
        if not (e.source == "Sysmon" and e.event_type == "3"):
            return []
        dst = e.destination_ip
        if not self.external(dst) or self.allowlisted_dest(dst, e.domain):
            return []
        img = basename(e.process_name)
        reasons = []
        if self.watchlisted(dst, e.domain):
            reasons.append("destination on watchlist")
        if self.user_writable(e.process_name):
            reasons.append("process runs from user-writable path")
        if img in self.NET_LOLBINS:
            reasons.append(f"{img} making direct network connection")
        if not reasons:
            return []
        key = (e.host, (e.process_name or "").lower(), dst, e.destination_port)
        if key in self._seen:  # aggregate repeats into the first detection
            det = self._seen[key]
            det.event_ids.append(e.event_id)
            det.end_time = e.timestamp
            return []
        tid = "T1071.001" if e.destination_port in (80, 443, 8080) else "T1571"
        watch = "destination on watchlist" in reasons
        sev = "HIGH" if watch or len(reasons) >= 2 else "MEDIUM"
        conf = 0.9 if watch else 0.55 + 0.1 * len(reasons)
        det = make_detection(self, [e], tid, sev, conf,
                             f"{img or 'process'} on {e.host} connected to {dst}:{e.destination_port}",
                             [f"Reasons: {', '.join(reasons)}", f"Process: {e.process_name}",
                              f"Destination: {dst}:{e.destination_port} {e.domain or ''}".strip()],
                             entities={"dst_ip": dst, "dst_port": e.destination_port, "process": e.process_name})
        self._seen[key] = det
        return [det]


# --------------------------------------------------------------------------- behavioural rules
def _bursts(items: List[NormalizedEvent], window: timedelta, threshold: int) -> List[List[NormalizedEvent]]:
    """Split time-sorted events into bursts where >= threshold occur within ``window``."""
    items = sorted(items, key=lambda x: x.timestamp)
    bursts, i, n = [], 0, len(items)
    while i < n:
        j = i
        while j + 1 < n and items[j + 1].timestamp - items[i].timestamp <= window:
            j += 1
        if j - i + 1 >= threshold:
            # extend while failures continue at the same cadence
            while j + 1 < n and items[j + 1].timestamp - items[j].timestamp <= window:
                j += 1
            bursts.append(items[i:j + 1])
            i = j + 1
        else:
            i += 1
    return bursts


class BruteForceRule(AggregateRule):
    rule_id = "CIA-CRD-002"
    name = "Brute force / password spraying"
    config_key = "brute_force"

    def evaluate_all(self, events, context):
        thr = int(self.cfg.get("threshold", 8))
        window = timedelta(minutes=float(self.cfg.get("window_minutes", 10)))
        succ_window = timedelta(minutes=float(self.cfg.get("success_window_minutes", 30)))
        failures = [e for e in events if e.source == "Windows Event Log" and e.event_type == "4625"]
        successes = [e for e in events if e.source == "Windows Event Log" and e.event_type == "4624"]
        out: List[Detection] = []

        by_target = defaultdict(list)
        for e in failures:
            by_target[(e.host, (e.username or "").lower(), e.source_ip)].append(e)
        for (host, user, src), group in by_target.items():
            for burst in _bursts(group, window, thr):
                ext = self.external(src)
                sev = "HIGH" if ext or len(burst) >= 2 * thr else "MEDIUM"
                conf = min(0.95, 0.6 + 0.1 * min(3, len(burst) / thr) + (0.05 if ext else 0))
                types = sorted({b.logon_type for b in burst if b.logon_type})
                det = make_detection(self, burst, "T1110.001", sev, conf,
                                     f"{len(burst)} failed logons for '{user}' on {host}"
                                     + (f" from {src}" if src else ""),
                                     [f"{len(burst)} x 4625 between {burst[0].timestamp:%H:%M:%S} and "
                                      f"{burst[-1].timestamp:%H:%M:%S}",
                                      f"Source IP: {src or 'n/a'} ({'external' if ext else 'internal/unknown'})",
                                      f"Logon types: {', '.join(types) or 'n/a'}"],
                                     entities={"src_ip": src, "target_user": user, "attempts": len(burst)})
                out.append(det)
                win = [s for s in successes
                       if (s.username or "").lower() == user and s.host == host
                       and (not src or not s.source_ip or s.source_ip == src)
                       and burst[0].timestamp <= s.timestamp <= burst[-1].timestamp + succ_window]
                if win:
                    s = min(win, key=lambda x: x.timestamp)
                    out.append(make_detection(
                        BruteForceSuccessRule(), [s], "T1078", "CRITICAL" if ext else "HIGH",
                        0.9 if ext else 0.8,
                        f"Successful logon for '{user}' on {host} after brute force",
                        [f"4624 at {s.timestamp:%H:%M:%S} following {len(burst)} failures",
                         f"Source IP: {s.source_ip or 'n/a'}", f"Logon type: {s.logon_type or 'n/a'}",
                         f"Linked brute-force detection: {det.detection_id}"],
                        tactic="Initial Access",
                        entities={"src_ip": s.source_ip, "linked_detection": det.detection_id}))

        # password spraying: one source, many users
        by_src = defaultdict(list)
        for e in failures:
            if e.source_ip:
                by_src[e.source_ip].append(e)
        spray_thr = max(5, thr // 2)
        for src, group in by_src.items():
            for burst in _bursts(group, window, spray_thr):
                users = {(b.username or "").lower() for b in burst}
                if len(users) >= spray_thr:
                    out.append(make_detection(self, burst, "T1110.003", "HIGH", 0.8,
                                              f"Password spraying from {src} against {len(users)} accounts",
                                              [f"Accounts: {', '.join(sorted(users)[:15])}"],
                                              entities={"src_ip": src}))
        return out


class BruteForceSuccessRule(DetectionRule):
    rule_id = "CIA-INI-001"
    name = "Logon after brute force"
    config_key = "brute_force"


# Backwards-compatible name used by earlier versions
FailedLoginRule = BruteForceRule


def _connection_attempts(events: List[NormalizedEvent]) -> List[NormalizedEvent]:
    """Outbound connection attempts (SYN packets or Sysmon EID 3)."""
    out = []
    for e in events:
        if not (e.destination_ip and e.source_ip):
            continue
        if e.source == "Sysmon" and e.event_type == "3":
            if str(e.raw_data.get("Initiated", "true")).lower() != "false":
                out.append(e)
        elif e.source == "Wireshark":
            info = (e.description or "").upper()
            if "[SYN]" in info and "ACK" not in info.split("[SYN")[1][:12]:
                out.append(e)
            elif "[" not in info and e.destination_port and e.destination_port < 49152:
                out.append(e)
    return out


class PortScanRule(AggregateRule):
    rule_id = "CIA-DIS-001"
    name = "Port / network scan"
    config_key = "port_scan"

    def evaluate_all(self, events, context):
        port_thr = int(self.cfg.get("distinct_ports", 15))
        host_thr = int(self.cfg.get("distinct_hosts", 20))
        window = timedelta(seconds=float(self.cfg.get("window_seconds", 120)))
        by_src = defaultdict(list)
        for e in _connection_attempts(events):
            if e.destination_port is not None:
                by_src[e.source_ip].append(e)
        out = []
        for src, group in by_src.items():
            group.sort(key=lambda x: x.timestamp)
            i = 0
            while i < len(group):
                j = i
                while j + 1 < len(group) and group[j + 1].timestamp - group[i].timestamp <= window:
                    j += 1
                chunk = group[i:j + 1]
                per_host = defaultdict(set)
                per_port = defaultdict(set)
                for c in chunk:
                    per_host[c.destination_ip].add(c.destination_port)
                    per_port[c.destination_port].add(c.destination_ip)
                vert = max(per_host.items(), key=lambda kv: len(kv[1]))
                horiz = max(per_port.items(), key=lambda kv: len(kv[1]))
                if len(vert[1]) >= port_thr or len(horiz[1]) >= host_thr:
                    ext = self.external(src)
                    tid = "T1595" if ext else "T1046"
                    big = len(vert[1]) >= 3 * port_thr or len(horiz[1]) >= 3 * host_thr
                    kind = (f"vertical scan of {vert[0]} ({len(vert[1])} ports)" if len(vert[1]) >= port_thr
                            else f"horizontal scan of port {horiz[0]} ({len(horiz[1])} hosts)")
                    out.append(make_detection(
                        self, chunk, tid, "HIGH" if big else "MEDIUM", 0.7 + (0.1 if ext else 0) + (0.1 if big else 0),
                        f"{'External' if ext else 'Internal'} {kind} from {src}",
                        [f"{len(chunk)} connection attempts in {(chunk[-1].timestamp - chunk[0].timestamp).total_seconds():.0f}s",
                         f"Ports probed: {', '.join(map(str, sorted(vert[1])[:25]))}"],
                        entities={"src_ip": src, "dst_ip": vert[0]}))
                    i = j + 1
                else:
                    i += 1
        return out


class BeaconingRule(AggregateRule):
    rule_id = "CIA-C2-003"
    name = "C2 beaconing"
    config_key = "beaconing"

    def evaluate_all(self, events, context):
        min_n = int(self.cfg.get("min_connections", 8))
        max_jit = float(self.cfg.get("max_jitter_ratio", 0.2))
        lo, hi = float(self.cfg.get("min_interval_seconds", 5)), float(self.cfg.get("max_interval_seconds", 3600))
        groups = defaultdict(list)
        for e in _connection_attempts(events):
            if self.external(e.destination_ip) and not self.allowlisted_dest(e.destination_ip, e.domain):
                groups[(e.source, e.source_ip, e.destination_ip, e.destination_port)].append(e)
        best: Dict[tuple, Detection] = {}
        for (src_kind, src, dst, port), group in groups.items():
            group.sort(key=lambda x: x.timestamp)
            # collapse retransmits / duplicate records closer than the minimum interval
            dedup = [group[0]]
            for g in group[1:]:
                if (g.timestamp - dedup[-1].timestamp).total_seconds() >= lo:
                    dedup.append(g)
            if len(dedup) < min_n:
                continue
            intervals = [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(dedup, dedup[1:])]
            med = statistics.median(intervals)
            if not (lo <= med <= hi):
                continue
            within = sum(1 for iv in intervals if abs(iv - med) <= max_jit * med) / len(intervals)
            if within < 0.8:
                continue
            mad = statistics.median([abs(iv - med) for iv in intervals])
            proc = next((g.process_name for g in dedup if g.process_name), None)
            conf = 0.5 + 0.4 * within + (0.05 if proc and self.user_writable(proc) else 0)
            tid = "T1071.001" if port in (80, 443, 8080) else "T1071"
            det = make_detection(
                self, dedup, tid, "HIGH", conf,
                f"Periodic beaconing from {src} to {dst}:{port} every ~{med:.0f}s",
                [f"{len(dedup)} connections, median interval {med:.1f}s, MAD {mad:.1f}s, "
                 f"{within:.0%} within ±{max_jit:.0%}",
                 f"Process: {proc}" if proc else f"Observed in {src_kind}",
                 f"Duration: {dedup[0].timestamp:%H:%M:%S} → {dedup[-1].timestamp:%H:%M:%S}"],
                entities={"src_ip": src, "dst_ip": dst, "dst_port": port, "interval_s": round(med, 1),
                          "process": proc})
            key = (src, dst, port)
            if key not in best or det.confidence > best[key].confidence:
                if key in best:
                    det.event_ids = list(dict.fromkeys(det.event_ids + best[key].event_ids))
                    det.evidence.append("Corroborated by a second log source")
                best[key] = det
            else:
                best[key].event_ids = list(dict.fromkeys(best[key].event_ids + det.event_ids))
                best[key].evidence.append("Corroborated by a second log source")
        dets = list(best.values())
        context.setdefault("c2_destinations", set()).update(d.entities["dst_ip"] for d in dets)
        return dets


class ExfiltrationRule(AggregateRule):
    rule_id = "CIA-EXF-001"
    name = "Potential data exfiltration"
    config_key = "exfiltration"

    def evaluate_all(self, events, context):
        thr = int(self.cfg.get("bytes_threshold", 10_000_000))
        window = timedelta(minutes=float(self.cfg.get("window_minutes", 60)))
        c2 = context.get("c2_destinations", set())
        flows = defaultdict(list)
        for e in events:
            if e.bytes_transferred and e.source_ip and e.destination_ip and \
                    not self.external(e.source_ip) and self.external(e.destination_ip) and \
                    not self.allowlisted_dest(e.destination_ip, e.domain):
                flows[(e.source_ip, e.destination_ip)].append(e)
        out = []
        for (src, dst), group in flows.items():
            group.sort(key=lambda x: x.timestamp)
            i, total, start = 0, 0, 0
            for i, e in enumerate(group):
                total += e.bytes_transferred
                while group[i].timestamp - group[start].timestamp > window:
                    total -= group[start].bytes_transferred
                    start += 1
                if total >= thr:
                    # extend to include the full transfer
                    end = i
                    while end + 1 < len(group) and group[end + 1].timestamp - group[end].timestamp <= window:
                        end += 1
                    chunk = group[start:end + 1]
                    size = sum(c.bytes_transferred for c in chunk)
                    via_c2 = dst in c2
                    tid = "T1041" if via_c2 else "T1048"
                    conf = 0.6 + (0.2 if via_c2 else 0) + (0.1 if size >= 5 * thr else 0)
                    out.append(make_detection(
                        self, chunk, tid, "CRITICAL" if via_c2 else "HIGH", conf,
                        f"{size / 1e6:.1f} MB sent from {src} to external {dst}",
                        [f"{len(chunk)} records totalling {size:,} bytes between "
                         f"{chunk[0].timestamp:%H:%M:%S} and {chunk[-1].timestamp:%H:%M:%S}",
                         "Destination is a detected C2 endpoint" if via_c2 else "Destination not allowlisted"],
                        entities={"src_ip": src, "dst_ip": dst, "bytes": size}))
                    break
        return out


EVENT_RULES = [SuspiciousPowerShellRule, LolbinRule, PersistenceRule, PrivilegeEscalationRule,
               CredentialAccessRule, DefenseEvasionRule, OfficeChildProcessRule, IngressToolTransferRule,
               SuspiciousNetworkConnectionRule]
# Order matters: beaconing populates context used by exfiltration
AGGREGATE_RULES = [BruteForceRule, PortScanRule, BeaconingRule, ExfiltrationRule]
