from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from config.detection_config import DEFAULT_RULE_CONFIG
from core.normalization import NormalizationEngine, ip_in_networks
from models.event_model import NormalizedEvent

# Common TLDs (keeps 'powershell.exe' / 'Net.WebClient' from being treated as domains)
_TLDS = set("""
com net org edu gov mil int info biz io co me ru cn su ir kp tk ml ga cf gq xyz top online site club
live app dev cloud tech store space pw cc ws in uk de fr nl be eu us ca au jp kr br ua pl it es ch se no
fi dk cz ro hu at pt gr tr il sa ae sg hk tw vn th my id ph mx ar cl za ng ke onion lol icu buzz work
link click shop vip win bid men today zip mov
""".split())
_FILE_EXTS = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "msi", "txt", "log", "dat",
              "tmp", "ini", "cfg", "xml", "json", "csv", "lnk", "sys", "evtx", "zip", "rar", "7z", "doc",
              "docx", "docm", "xls", "xlsx", "xlsm", "pdf", "png", "jpg"}
_SUSPICIOUS_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".msi",
                   ".lnk", ".jar", ".sh", ".elf", ".bin", ".zip", ".7z", ".rar", ".dmp")

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?(?::[0-9a-fA-F]{1,4}){0,6}(?![\w:])")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()]+", re.I)
DOMAIN_RE = re.compile(r"(?<![\w.\\/@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?![\w.-])", re.I)
MD5_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
SHA1_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
SHA256_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
WINPATH_RE = re.compile(r"(?:[a-zA-Z]:\\|\\\\[\w.$-]+\\)[^\s\"'<>|*?\r\n,;]+")
UNIXPATH_RE = re.compile(r"(?<![\w:/])/(?:tmp|dev/shm|var/tmp)/[^\s\"'<>|;]+")


class IOCExtractor:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        g = (config or DEFAULT_RULE_CONFIG).get("global", DEFAULT_RULE_CONFIG["global"])
        self.internal = g["internal_cidrs"]
        self.allow_cidrs = g["allowlisted_cidrs"]
        self.allow_domains = [d.lower() for d in g["allowlisted_domains"]]
        self.writable = [p.lower() for p in g["user_writable_paths"]]
        # Kept for backwards compatibility
        self.ip_pattern = IPV4_RE
        self.domain_pattern = DOMAIN_RE

    # ------------------------------------------------------------------ public
    def extract(self, events: List[NormalizedEvent], detections: Optional[list] = None) -> List[Dict[str, Any]]:
        det_by_event: Dict[str, list] = {}
        for d in detections or []:
            for eid in d.event_ids:
                det_by_event.setdefault(eid, []).append(d)

        table: Dict[tuple, Dict[str, Any]] = {}
        for event in events:
            found = self.extract_from_event(event)
            event.iocs = [f"{t}:{v}" for t, v in found]
            if found and not event.ioc_value:
                event.ioc_type, event.ioc_value = found[0]
            dets = det_by_event.get(event.event_id, [])
            for ioc_type, value in found:
                rec = table.get((ioc_type, value))
                if rec is None:
                    rec = table[(ioc_type, value)] = {
                        "IOC": value, "Type": ioc_type, "Source Event ID": event.event_id,
                        "first_seen": event.timestamp, "last_seen": event.timestamp, "count": 0,
                        "event_ids": [], "hosts": set(), "sources": set(), "rules": set(),
                        "techniques": set(), "evidence_refs": [],
                        "scope": self._scope(ioc_type, value),
                    }
                rec["count"] += 1
                rec["first_seen"] = min(rec["first_seen"], event.timestamp)
                rec["last_seen"] = max(rec["last_seen"], event.timestamp)
                if len(rec["event_ids"]) < 200:
                    rec["event_ids"].append(event.event_id)
                    rec["evidence_refs"].append(event.evidence_ref)
                if event.host:
                    rec["hosts"].add(event.host)
                rec["sources"].add(event.source)
                for d in dets:
                    rec["rules"].add(d.rule_name)
                    rec["techniques"].add(d.technique_id)

        out = []
        for rec in table.values():
            rec["malicious_context"] = bool(rec["rules"])
            for k in ("hosts", "sources", "rules", "techniques"):
                rec[k] = sorted(rec[k])
            out.append(rec)
        out.sort(key=lambda r: (not r["malicious_context"], r["scope"] != "external", -r["count"]))
        return out

    def extract_from_event(self, event: NormalizedEvent) -> List[tuple]:
        """Return de-duplicated (type, value) IOCs present in one event."""
        found: Dict[tuple, None] = {}
        decoded = NormalizationEngine.decode_powershell(event.command_line)
        texts = [event.command_line, decoded, event.file_path, event.registry_key,
                 event.raw_data.get("Details"), event.raw_data.get("QueryResults"),
                 event.raw_data.get("TaskContent"), event.raw_data.get("ImagePath")]
        if event.source != "Windows Event Log":  # Security log messages are boilerplate-heavy
            texts.append(event.description)

        for algo, digest in (event.hashes or {}).items():
            if algo in ("MD5", "SHA1", "SHA256"):
                found[(algo, digest.lower())] = None
        for ip in (event.source_ip, event.destination_ip):
            ip = NormalizationEngine.normalize_ip(ip)
            if ip and not ip_in_networks(ip, self.internal):
                found[(self._ip_type(ip), ip)] = None
        if event.domain:
            dom = event.domain.lower().rstrip(".")
            if self._valid_domain(dom):
                found[("Domain", dom)] = None
        if event.process_name and self._suspicious_path(event.process_name):
            found[("File Path", event.process_name.strip('"'))] = None

        for text in filter(None, texts):
            self._scan_text(str(text), found)
        return list(found.keys())

    # ------------------------------------------------------------------ internals
    def _scan_text(self, text: str, found: Dict[tuple, None]):
        url_spans = []
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;:)]}'\"")
            url_spans.append(m.span())
            found[("URL", url)] = None
            host = (urlparse(url).hostname or "").lower()
            ip = NormalizationEngine.normalize_ip(host)
            if ip:
                found[(self._ip_type(ip), ip)] = None
            elif self._valid_domain(host):
                found[("Domain", host)] = None
        for m in IPV4_RE.finditer(text):
            ip = NormalizationEngine.normalize_ip(m.group(0))
            if ip and not ip.startswith("0."):
                found[("IPv4", ip)] = None
        for m in IPV6_RE.finditer(text):
            cand = m.group(0)
            if cand.count(":") < 2 or len(cand) < 6:
                continue
            try:
                addr = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            found[("IPv6", str(addr))] = None
        for m in DOMAIN_RE.finditer(text):
            if any(s <= m.start() < e for s, e in url_spans):
                continue
            dom = m.group(0).lower()
            if self._valid_domain(dom):
                found[("Domain", dom)] = None
        for rx, label in ((SHA256_RE, "SHA256"), (SHA1_RE, "SHA1"), (MD5_RE, "MD5")):
            for m in rx.finditer(text):
                found[(label, m.group(0).lower())] = None
        for rx in (WINPATH_RE, UNIXPATH_RE):
            for m in rx.finditer(text):
                path = m.group(0).rstrip(".,;)'\"")
                if self._suspicious_path(path):
                    found[("File Path", path)] = None

    def _valid_domain(self, dom: str) -> bool:
        if not dom or "." not in dom or NormalizationEngine.normalize_ip(dom):
            return False
        tld = dom.rsplit(".", 1)[-1]
        if tld in _FILE_EXTS or tld not in _TLDS:
            return False
        labels = dom.split(".")
        return len(labels) >= 2 and all(labels)

    def _suspicious_path(self, path: str) -> bool:
        low = path.lower().strip('"')
        if "\\start menu\\programs\\startup\\" in low:
            return True
        return any(m in low for m in self.writable) and low.endswith(_SUSPICIOUS_EXT)

    @staticmethod
    def _ip_type(ip: str) -> str:
        return "IPv6" if ":" in ip else "IPv4"

    def _scope(self, ioc_type: str, value: str) -> str:
        if ioc_type in ("IPv4", "IPv6"):
            if ip_in_networks(value, self.allow_cidrs):
                return "allowlisted"
            return "internal" if ip_in_networks(value, self.internal) else "external"
        if ioc_type in ("Domain", "URL"):
            host = value if ioc_type == "Domain" else (urlparse(value).hostname or "")
            if any(host == d or host.endswith("." + d) for d in self.allow_domains):
                return "allowlisted"
            return "external"
        return "host"


def iocs_for_values(iocs: Iterable[Dict[str, Any]], values: Iterable[str]) -> List[Dict[str, Any]]:
    wanted = set(values)
    return [i for i in iocs if i["IOC"] in wanted]
