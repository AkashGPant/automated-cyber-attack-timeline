from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from config.config import REPORTS_DIR
from detection.mitre_mapping import technique
from models.event_model import NormalizedEvent
from reports.recommendations import recommendations_for

REPORT_VERSION = "2.0"


def _jsonable(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


class ReportGenerator:
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or REPORTS_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------ legacy API (kept)
    def generate_csv(self, events: List[NormalizedEvent], filename="forensic_report.csv") -> str:
        df = pd.DataFrame([e.to_dict() for e in events])
        path = os.path.join(self.output_dir, filename)
        df.to_csv(path, index=False)
        return path

    def generate_json(self, events: List[NormalizedEvent], filename="forensic_report.json", result=None) -> str:
        data: Any = self.build_report(result) if result is not None else [e.to_dict() for e in events]
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=_jsonable)
        return path

    # ------------------------------------------------------------------ full report
    def build_report(self, result) -> Dict[str, Any]:
        s = result.summary
        incidents = []
        for inc in result.incidents:
            d = inc.to_dict()
            d["recommendations"] = recommendations_for(inc.techniques, inc.severity)
            d["mitre"] = [self._mitre_entry(t, [x for x in inc.detections if x.technique_id == t])
                          for t in inc.techniques]
            incidents.append(d)
        mitre = [self._mitre_entry(t, [d for d in result.detections if d.technique_id == t])
                 for t in sorted({d.technique_id for d in result.detections})]
        return {
            "report_metadata": {
                "tool": "CyberIA", "report_version": REPORT_VERSION,
                "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "evidence_files": [vars(p) for p in result.parse_reports],
                "timestamps": "All times normalized to UTC",
            },
            "executive_summary": {**s, "narrative": self.narrative(result)},
            "incidents": incidents,
            "detections": [d.to_dict() for d in result.detections],
            "mitre_attack": mitre,
            "iocs": [self._ioc_row(i) for i in result.iocs],
            "process_trees": {h: [n.to_dict() for n in nodes if n.detection_ids or not n.synthetic]
                              for h, nodes in result.process_trees.items()
                              if any(n.detection_ids for n in nodes)},
            "recommendations": recommendations_for(s.get("techniques", []), s.get("overall_severity", "")),
            "timeline": [e.to_dict() for e in result.events if e.detection_ids or e.incident_id],
        }

    @staticmethod
    def _mitre_entry(tid: str, dets) -> Dict[str, Any]:
        t = technique(tid)
        return {"technique_id": tid, "technique": t["name"], "tactics": t["tactics"], "url": t["url"],
                "detections": len(dets), "max_severity": max((d.severity for d in dets),
                                                               key=lambda s: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s)
                                                               if s in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else -1,
                                                               default=None),
                "hosts": sorted({d.host for d in dets if d.host})}

    @staticmethod
    def _ioc_row(i: Dict[str, Any]) -> Dict[str, Any]:
        row = dict(i)
        for k in ("first_seen", "last_seen"):
            if isinstance(row.get(k), datetime):
                row[k] = row[k].isoformat()
        return row

    @staticmethod
    def narrative(result) -> str:
        s = result.summary
        if not result.incidents:
            return (f"Analyzed {s['total_events']} events; no incidents were identified "
                    f"({s['total_detections']} standalone detections).")
        top = max(result.incidents, key=lambda i: i.score)
        parts = [f"Analyzed {s['total_events']} events from {len(s['events_by_source'])} log source(s) "
                 f"and identified {s['total_incidents']} incident(s) across {len(s['affected_hosts'])} host(s).",
                 f"Highest-risk incident {top.incident_id} ({top.severity}, score {top.score}): {top.title} on "
                 f"{', '.join(top.hosts) or 'network'} between {top.start:%Y-%m-%d %H:%M} and {top.end:%H:%M} UTC.",
                 "Observed tactics: " + " → ".join(top.tactics) + "."]
        if top.users:
            parts.append(f"Involved account(s): {', '.join(top.users)}.")
        return " ".join(parts)

    # ------------------------------------------------------------------ tabular exports
    def tables(self, result) -> Dict[str, pd.DataFrame]:
        inc_rows, chain_rows = [], []
        for inc in result.incidents:
            inc_rows.append({
                "incident_id": inc.incident_id, "title": inc.title, "severity": inc.severity,
                "risk_score": inc.score, "start_utc": inc.start.isoformat(), "end_utc": inc.end.isoformat(),
                "hosts": "; ".join(inc.hosts), "users": "; ".join(inc.users),
                "tactics": " → ".join(inc.tactics), "techniques": "; ".join(inc.techniques),
                "patterns": "; ".join(inc.patterns), "detections": len(inc.detections),
                "iocs": "; ".join(inc.iocs), "risk_explanation": " | ".join(inc.score_explanation),
                "recommendations": " | ".join(recommendations_for(inc.techniques, inc.severity)),
            })
            for step in inc.chain:
                chain_rows.append({"incident_id": inc.incident_id, **{k: v for k, v in step.items()
                                                                      if k != "incident_id"},
                                   "detection_ids": "; ".join(step["detection_ids"]),
                                   "evidence": " | ".join(step["evidence"]),
                                   "evidence_refs": "; ".join(step["evidence_refs"])})
        det_rows = []
        for d in result.detections:
            row = d.to_dict()
            row["evidence"] = " | ".join(row["evidence"])
            row["evidence_refs"] = "; ".join(row["evidence_refs"])
            row["event_ids"] = "; ".join(row["event_ids"])
            row["entities"] = json.dumps(row["entities"], default=_jsonable)
            row["score_explanation"] = " | ".join(row["score_explanation"])
            det_rows.append(row)
        ioc_rows = []
        for i in result.iocs:
            r = self._ioc_row(i)
            for k in ("event_ids", "evidence_refs", "hosts", "sources", "rules", "techniques"):
                r[k] = "; ".join(map(str, r.get(k, [])))
            ioc_rows.append(r)
        return {
            "incidents": pd.DataFrame(inc_rows),
            "attack_chains": pd.DataFrame(chain_rows),
            "detections": pd.DataFrame(det_rows),
            "iocs": pd.DataFrame(ioc_rows),
            "events": pd.DataFrame([e.to_dict() for e in result.events]),
        }

    def generate_all(self, result, prefix: str = "cyberia") -> Dict[str, str]:
        """Write the JSON report and every CSV table to the reports directory."""
        paths = {"json": self.generate_json(result.events, f"{prefix}_report.json", result=result)}
        for name, df in self.tables(result).items():
            path = os.path.join(self.output_dir, f"{prefix}_{name}.csv")
            df.to_csv(path, index=False)
            paths[name] = path
        return paths

    def build_zip(self, result) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("report.json", json.dumps(self.build_report(result), indent=2, default=_jsonable))
            for name, df in self.tables(result).items():
                zf.writestr(f"{name}.csv", df.to_csv(index=False))
        return buf.getvalue()
