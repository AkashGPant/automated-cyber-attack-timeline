"""Event correlation: host/IP enrichment, process trees, incident grouping and
attack-chain reconstruction."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set

from config.detection_config import DEFAULT_RULE_CONFIG
from core.normalization import is_external_ip
from detection.mitre_mapping import tactic_rank
from models.detection_model import Detection, severity_rank
from models.event_model import NormalizedEvent

C2_TECHNIQUES = ("T1071", "T1571", "T1105", "T1041")

# (name, ordered stages); each stage is a tuple of technique-id prefixes
ATTACK_PATTERNS = [
    ("Brute force → Valid logon → PowerShell → C2",
     [("T1110",), ("T1078",), ("T1059.001",), C2_TECHNIQUES]),
    ("Reconnaissance → Brute force → Account takeover",
     [("T1595", "T1046"), ("T1110",), ("T1078",)]),
    ("Malicious document → Proxy execution → C2",
     [("T1204",), ("T1218", "T1059", "T1047", "T1105"), C2_TECHNIQUES]),
    ("Execution → Persistence → Command and Control",
     [("T1059", "T1218", "T1204", "T1047"), ("T1547", "T1053", "T1543", "T1136", "T1197"), C2_TECHNIQUES]),
    ("Privilege escalation → Credential dumping",
     [("T1098", "T1548", "T1078"), ("T1003",)]),
    ("C2 established → Data exfiltration",
     [C2_TECHNIQUES, ("T1041", "T1048", "T1567")]),
]


@dataclass
class ProcessNode:
    key: str
    host: str
    pid: Optional[int]
    ppid: Optional[int]
    image: str
    command_line: Optional[str]
    user: Optional[str]
    start: datetime
    parent_key: Optional[str] = None
    synthetic: bool = False
    event_ids: List[str] = field(default_factory=list)
    detection_ids: List[str] = field(default_factory=list)
    severity: str = "INFO"
    activity: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "host": self.host, "pid": self.pid, "ppid": self.ppid, "image": self.image,
            "command_line": self.command_line, "user": self.user,
            "start": self.start.isoformat() if self.start and self.start != datetime.min else None,
            "parent_key": self.parent_key, "synthetic": self.synthetic, "severity": self.severity,
            "detection_ids": self.detection_ids, "activity": self.activity[:20],
        }


@dataclass
class Incident:
    incident_id: str
    title: str
    hosts: List[str]
    users: List[str]
    start: datetime
    end: datetime
    detections: List[Detection]
    chain: List[Dict[str, Any]]
    patterns: List[str]
    tactics: List[str]
    techniques: List[str]
    related_event_ids: List[str]
    linkage: List[str]
    iocs: List[str] = field(default_factory=list)
    score: int = 0
    severity: str = "INFO"
    score_explanation: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id, "title": self.title, "severity": self.severity,
            "risk_score": self.score, "risk_explanation": self.score_explanation,
            "start": self.start.isoformat(), "end": self.end.isoformat(),
            "duration_minutes": round((self.end - self.start).total_seconds() / 60, 1),
            "hosts": self.hosts, "users": self.users, "log_sources": self.sources,
            "tactics": self.tactics, "techniques": self.techniques,
            "matched_patterns": self.patterns, "attack_chain": self.chain,
            "linkage_evidence": self.linkage, "iocs": self.iocs,
            "detection_ids": [d.detection_id for d in self.detections],
            "related_event_ids": self.related_event_ids,
        }


def _norm_host(h: Optional[str]) -> str:
    return (h or "").strip().lower()


def _base(path: Optional[str]) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


class CorrelationEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None, incident_window_hours: float = 6.0):
        cfg = config or DEFAULT_RULE_CONFIG
        self.internal = cfg.get("global", DEFAULT_RULE_CONFIG["global"])["internal_cidrs"]
        self.window = timedelta(hours=incident_window_hours)
        self.ip_to_host: Dict[str, str] = {}

    # ------------------------------------------------------------------ timeline
    def correlate(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        """Sort chronologically and fill missing hosts from learned IP→host bindings."""
        events.sort(key=lambda x: x.timestamp)
        self.ip_to_host = self.learn_ip_hosts(events)
        for e in events:
            if not e.host:
                e.host = self.ip_to_host.get(e.source_ip or "") or self.ip_to_host.get(e.destination_ip or "")
        return events

    def learn_ip_hosts(self, events: Iterable[NormalizedEvent]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for e in events:
            if e.source == "Sysmon" and e.event_type == "3" and e.host and e.source_ip \
                    and not is_external_ip(e.source_ip, self.internal) \
                    and str(e.raw_data.get("Initiated", "true")).lower() != "false":
                mapping.setdefault(e.source_ip, e.host)
            elif e.raw_data.get("HostIp") and e.host:
                mapping.setdefault(e.raw_data["HostIp"], e.host)
        return mapping

    # ------------------------------------------------------------------ process trees
    def build_process_trees(self, events: List[NormalizedEvent],
                            detections: Optional[List[Detection]] = None) -> Dict[str, List[ProcessNode]]:
        det_by_event = defaultdict(list)
        for d in detections or []:
            for eid in d.event_ids:
                det_by_event[eid].append(d)

        nodes: Dict[str, ProcessNode] = {}
        by_pid: Dict[tuple, List[ProcessNode]] = defaultdict(list)  # (host, pid) -> nodes by start

        def find(host: str, pid: Optional[int], when: datetime) -> Optional[ProcessNode]:
            if pid is None:
                return None
            cands = [n for n in by_pid.get((host, pid), []) if n.start <= when + timedelta(seconds=2)]
            return max(cands, key=lambda n: n.start) if cands else None

        creations = [e for e in events if e.process_id is not None and e.host and (
            (e.source == "Sysmon" and e.event_type == "1") or
            (e.source == "Windows Event Log" and e.event_type == "4688"))]
        creations.sort(key=lambda e: e.timestamp)
        for e in creations:
            host = _norm_host(e.host)
            existing = find(host, e.process_id, e.timestamp)
            if existing and abs((existing.start - e.timestamp).total_seconds()) <= 2 \
                    and _base(existing.image) == _base(e.process_name):
                node = existing  # same process seen by Sysmon and Security log
            else:
                node = ProcessNode(key=f"{host}|{e.process_id}|{e.timestamp:%Y%m%d%H%M%S%f}", host=e.host,
                                   pid=e.process_id, ppid=e.parent_process_id, image=e.process_name or "?",
                                   command_line=e.command_line, user=e.username, start=e.timestamp)
                parent = find(host, e.parent_process_id, e.timestamp)
                if parent is None and (e.parent_process or e.parent_process_id is not None):
                    pkey = f"{host}|{e.parent_process_id}|{_base(e.parent_process)}|synthetic"
                    parent = nodes.get(pkey)
                    if parent is None:
                        parent = ProcessNode(key=pkey, host=e.host, pid=e.parent_process_id, ppid=None,
                                             image=e.parent_process or "?", command_line=None, user=None,
                                             start=datetime.min, synthetic=True)
                        nodes[pkey] = parent
                        by_pid[(host, e.parent_process_id)].insert(0, parent)
                node.parent_key = parent.key if parent else None
                nodes[node.key] = node
                by_pid[(host, e.process_id)].append(node)
            node.event_ids.append(e.event_id)
            self._mark(node, det_by_event.get(e.event_id, []))

        # attach activity (network, file, registry, DNS...) to owning process
        for e in events:
            if e.process_id is None or not e.host:
                continue
            if (e.source == "Sysmon" and e.event_type == "1") or e.event_type == "4688":
                continue
            node = find(_norm_host(e.host), e.process_id, e.timestamp)
            if node:
                node.event_ids.append(e.event_id)
                label = (e.description or "")[:120]
                if label and len(node.activity) < 50:
                    node.activity.append(f"{e.timestamp:%H:%M:%S} {label}")
                self._mark(node, det_by_event.get(e.event_id, []))

        trees: Dict[str, List[ProcessNode]] = defaultdict(list)
        for n in nodes.values():
            trees[n.host].append(n)
        for host in trees:
            trees[host].sort(key=lambda n: (n.start, n.pid or 0))
        return dict(trees)

    @staticmethod
    def _mark(node: ProcessNode, dets: List[Detection]):
        for d in dets:
            if d.detection_id not in node.detection_ids:
                node.detection_ids.append(d.detection_id)
            if severity_rank(d.severity) > severity_rank(node.severity):
                node.severity = d.severity

    @staticmethod
    def ancestors(node_key: str, index: Dict[str, ProcessNode]) -> List[str]:
        out, seen = [], set()
        cur = index.get(node_key)
        while cur and cur.parent_key and cur.parent_key not in seen:
            seen.add(cur.parent_key)
            out.append(cur.parent_key)
            cur = index.get(cur.parent_key)
        return out

    # ------------------------------------------------------------------ incidents
    def build_incidents(self, events: List[NormalizedEvent], detections: List[Detection],
                        trees: Optional[Dict[str, List[ProcessNode]]] = None) -> List[Incident]:
        if not detections:
            return []
        trees = trees if trees is not None else self.build_process_trees(events, detections)
        by_id = {e.event_id: e for e in events}
        node_index = {n.key: n for nodes in trees.values() for n in nodes}
        event_node: Dict[str, str] = {}
        for n in node_index.values():
            for eid in n.event_ids:
                event_node.setdefault(eid, n.key)

        def det_nodes(d: Detection) -> Set[str]:
            return {event_node[e] for e in d.event_ids if e in event_node}

        def det_ips(d: Detection) -> Set[str]:
            ips = set()
            for k in ("src_ip", "dst_ip"):
                v = d.entities.get(k)
                if v and is_external_ip(v, self.internal):
                    ips.add(v)
            for eid in d.event_ids[:50]:
                e = by_id.get(eid)
                if e:
                    for v in (e.source_ip, e.destination_ip):
                        if v and is_external_ip(v, self.internal):
                            ips.add(v)
            return ips

        n = len(detections)
        parent = list(range(n))

        def root(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a, b):
            parent[root(a)] = root(b)

        ips = [det_ips(d) for d in detections]
        dnodes = [det_nodes(d) for d in detections]
        lineage = [set().union(*[{k, *self.ancestors(k, node_index)} for k in ns]) if ns else set()
                   for ns in dnodes]
        for i in range(n):
            for j in range(i + 1, n):
                a, b = detections[i], detections[j]
                close = abs((a.timestamp - b.timestamp)) <= self.window
                same_host = a.host and b.host and _norm_host(a.host) == _norm_host(b.host)
                if (same_host and close) or (ips[i] & ips[j] and close) or (lineage[i] & dnodes[j]) \
                        or (lineage[j] & dnodes[i]):
                    union(i, j)

        groups: Dict[int, List[int]] = defaultdict(list)
        for i in range(n):
            groups[root(i)].append(i)

        incidents = []
        for members in groups.values():
            dets = sorted((detections[i] for i in members), key=lambda d: d.timestamp)
            inc = self._make_incident(dets, by_id, node_index, event_node,
                                      set().union(*(ips[i] for i in members)))
            incidents.append(inc)
        incidents.sort(key=lambda x: x.start)
        for idx, inc in enumerate(incidents, start=1):
            inc.incident_id = f"INC-{idx:03d}"
            for d in inc.detections:
                d.incident_id = inc.incident_id
            for step in inc.chain:
                step["incident_id"] = inc.incident_id
            for eid in inc.related_event_ids:
                if eid in by_id:
                    by_id[eid].incident_id = inc.incident_id
        return incidents

    def _make_incident(self, dets: List[Detection], by_id, node_index, event_node, ext_ips) -> Incident:
        hosts = sorted({d.host for d in dets if d.host})
        users = sorted({d.user for d in dets if d.user and d.user.lower() not in ("system", "-")})
        start = dets[0].timestamp
        end = max((d.end_time or d.timestamp) for d in dets)

        # attack chain: one step per technique occurrence, merging consecutive repeats
        chain: List[Dict[str, Any]] = []
        for d in dets:
            if chain and chain[-1]["technique_id"] == d.technique_id and chain[-1]["host"] == d.host:
                step = chain[-1]
                step["detection_ids"].append(d.detection_id)
                step["occurrences"] += 1
                step["end"] = (d.end_time or d.timestamp).isoformat()
                if severity_rank(d.severity) > severity_rank(step["severity"]):
                    step["severity"] = d.severity
                continue
            chain.append({
                "step": len(chain) + 1, "time": d.timestamp.isoformat(),
                "end": (d.end_time or d.timestamp).isoformat(), "tactic": d.tactic,
                "technique_id": d.technique_id, "technique": d.technique_name, "host": d.host,
                "user": d.user, "severity": d.severity, "description": d.description,
                "detection_ids": [d.detection_id], "occurrences": 1, "link_to_previous": "",
                "evidence": d.evidence[:3], "evidence_refs": d.evidence_refs[:5],
            })
        det_index = {d.detection_id: d for d in dets}
        linkage: List[str] = []
        for prev, cur in zip(chain, chain[1:]):
            reasons = self._link_reasons(det_index[prev["detection_ids"][-1]], det_index[cur["detection_ids"][0]],
                                         by_id, node_index, event_node)
            cur["link_to_previous"] = "; ".join(reasons)
            for r in reasons:
                if r not in linkage:
                    linkage.append(r)

        techniques = list(dict.fromkeys(d.technique_id for d in dets))
        tactics = sorted({d.tactic for d in dets}, key=tactic_rank)
        patterns = [name for name, stages in ATTACK_PATTERNS if self._matches(dets, stages)]

        related = self._related_events(dets, by_id, node_index, event_node, ext_ips, hosts, start, end)
        if patterns:
            title = patterns[0]
        else:
            title = f"{dets[-1].tactic if len(tactics) == 1 else 'Multi-stage activity'} on {', '.join(hosts) or 'network'}"
        sources = sorted({by_id[e].source for d in dets for e in d.event_ids if e in by_id})
        return Incident(incident_id="", title=title, hosts=hosts, users=users, start=start, end=end,
                        detections=dets, chain=chain, patterns=patterns, tactics=tactics,
                        techniques=techniques, related_event_ids=related, linkage=linkage,
                        iocs=sorted(ext_ips), sources=sources)

    @staticmethod
    def _matches(dets: List[Detection], stages) -> bool:
        idx = 0
        for d in dets:  # time ordered
            if idx < len(stages) and d.technique_id.startswith(tuple(stages[idx])):
                idx += 1
        return idx == len(stages)

    def _link_reasons(self, a: Detection, b: Detection, by_id, node_index, event_node) -> List[str]:
        reasons = []
        an = {event_node[e] for e in a.event_ids if e in event_node}
        bn = {event_node[e] for e in b.event_ids if e in event_node}
        for bk in bn:
            anc = self.ancestors(bk, node_index)
            hit = an & ({bk} | set(anc))
            if hit:
                pa, pb = node_index[next(iter(hit))], node_index[bk]
                reasons.append(f"Process lineage: {_base(pa.image)}({pa.pid}) → {_base(pb.image)}({pb.pid})"
                               if pa.key != pb.key else f"Same process: {_base(pb.image)}({pb.pid})")
                break
        if a.user and b.user and a.user.lower() == b.user.lower():
            reasons.append(f"Same user: {a.user}")
        a_ips = {a.entities.get("src_ip"), a.entities.get("dst_ip")} - {None}
        b_ips = {b.entities.get("src_ip"), b.entities.get("dst_ip")} - {None}
        for e in a.event_ids[:20]:
            ev = by_id.get(e)
            if ev:
                a_ips |= {ev.source_ip, ev.destination_ip} - {None}
        for e in b.event_ids[:20]:
            ev = by_id.get(e)
            if ev:
                b_ips |= {ev.source_ip, ev.destination_ip} - {None}
        shared = sorted(ip for ip in a_ips & b_ips if is_external_ip(ip, self.internal))
        if shared:
            reasons.append(f"Shared IP: {', '.join(shared[:3])}")
        if a.host and b.host and _norm_host(a.host) == _norm_host(b.host):
            gap = (b.timestamp - (a.end_time or a.timestamp)).total_seconds() / 60
            reasons.append(f"Same host {a.host}, {max(gap, 0):.0f} min later")
        return reasons

    def _related_events(self, dets, by_id, node_index, event_node, ext_ips, hosts, start, end) -> List[str]:
        related = list(dict.fromkeys(e for d in dets for e in d.event_ids))
        flagged_nodes = {event_node[e] for e in related if e in event_node}
        # descendants of flagged processes
        children = defaultdict(list)
        for n in node_index.values():
            if n.parent_key:
                children[n.parent_key].append(n.key)
        stack, seen = list(flagged_nodes), set()
        while stack:
            k = stack.pop()
            if k in seen:
                continue
            seen.add(k)
            stack.extend(children.get(k, []))
        for k in seen:
            related.extend(node_index[k].event_ids)
        # events touching the incident's external infrastructure on its hosts
        hostset = {_norm_host(h) for h in hosts}
        for e in by_id.values():
            if start - timedelta(minutes=5) <= e.timestamp <= end + timedelta(minutes=5) and \
                    ({e.source_ip, e.destination_ip} & ext_ips) and \
                    (not hostset or _norm_host(e.host) in hostset or not e.host):
                related.append(e.event_id)
        return list(dict.fromkeys(related))
