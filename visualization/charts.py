"""Plotly chart builders for the SOC dashboard. Dark theme; palette validated
against the dataviz skill (status + categorical ramps on a #1a1a19 surface)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.graph_objects as go

# Status palette (reserved, dark-surface variants)
SEV_COLOR = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219",
             "LOW": "#3987e5", "INFO": "#898781"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
# Categorical ramp (dark) for tactics / sources
CAT = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]

SURFACE = "#1a1a19"
PLANE = "#0d0d0d"
INK = "#f0efec"
INK2 = "#c3c2b7"
MUTED = "#898781"
GRID = "#2c2c2a"

_LAYOUT = dict(paper_bgcolor=PLANE, plot_bgcolor=SURFACE, font=dict(color=INK2, size=12),
               title=dict(font=dict(color=INK, size=15)),
               margin=dict(l=60, r=24, t=50, b=44), legend=dict(bgcolor="rgba(0,0,0,0)"),
               xaxis=dict(gridcolor=GRID, zerolinecolor=GRID, linecolor="#383835", color=MUTED),
               yaxis=dict(gridcolor=GRID, zerolinecolor=GRID, linecolor="#383835", color=MUTED))


def _layout(title=None, **over):
    """Merge base layout with overrides; title becomes a styled title dict."""
    lay = {k: (dict(v) if isinstance(v, dict) else v) for k, v in _LAYOUT.items()}
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(lay.get(k), dict):
            lay[k].update(v)
        else:
            lay[k] = v
    if title is not None:
        lay["title"] = {**lay.get("title", {}), "text": title}
    return lay


def _empty(msg="No data"):
    fig = go.Figure()
    fig.update_layout(**_layout(height=240,
                      annotations=[dict(text=msg, showarrow=False, font=dict(color=MUTED, size=14))]))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return fig


def _cat(i: int) -> str:
    return CAT[i % len(CAT)]


def severity_timeline(df: pd.DataFrame):
    """Scatter timeline of events, y = severity band, colored by severity."""
    if df is None or df.empty:
        return _empty()
    d = df.copy()
    d["timestamp"] = pd.to_datetime(d["timestamp"], errors="coerce")
    d = d.dropna(subset=["timestamp"])
    d["severity"] = d["severity"].fillna("INFO")
    fig = go.Figure()
    for sev in SEV_ORDER:
        sub = d[d["severity"] == sev]
        if sub.empty:
            continue
        fig.add_trace(go.Scatter(
            x=sub["timestamp"], y=[sev] * len(sub), mode="markers", name=sev,
            marker=dict(color=SEV_COLOR[sev], size=9, line=dict(width=1, color=SURFACE)),
            customdata=sub[["source", "event_type", "host", "description"]].fillna("").values,
            hovertemplate="<b>%{x|%Y-%m-%d %H:%M:%S}</b><br>%{customdata[0]} / %{customdata[1]}"
                          "<br>host: %{customdata[2]}<br>%{customdata[3]}<extra>" + sev + "</extra>"))
    fig.update_layout(**_layout("Event timeline", height=360,
                      legend=dict(orientation="h", y=1.12, bgcolor="rgba(0,0,0,0)")))
    fig.update_yaxes(categoryorder="array", categoryarray=SEV_ORDER[::-1])
    return fig


def severity_bar(detections: List[Dict[str, Any]]):
    if not detections:
        return _empty("No detections")
    counts = pd.Series([d["severity"] for d in detections]).value_counts()
    order = [s for s in SEV_ORDER if s in counts.index]
    fig = go.Figure(go.Bar(
        x=[counts[s] for s in order], y=order, orientation="h",
        marker=dict(color=[SEV_COLOR[s] for s in order]),
        text=[counts[s] for s in order], textposition="outside",
        hovertemplate="%{y}: %{x} detection(s)<extra></extra>"))
    fig.update_layout(**_layout("Detections by severity", height=260))
    fig.update_xaxes(title="Count")
    return fig


def tactic_bar(detections: List[Dict[str, Any]]):
    if not detections:
        return _empty("No detections")
    counts = pd.Series([d["tactic"] for d in detections]).value_counts()
    fig = go.Figure(go.Bar(
        x=counts.values, y=counts.index, orientation="h",
        marker=dict(color=[_cat(i) for i in range(len(counts))]),
        text=counts.values, textposition="outside",
        hovertemplate="%{y}: %{x}<extra></extra>"))
    fig.update_layout(**_layout("Detections by ATT&CK tactic", height=max(260, 34 * len(counts) + 90)))
    fig.update_xaxes(title="Count")
    return fig


def mitre_matrix(detections: List[Dict[str, Any]], tactic_order: List[str]):
    """Heatmap-style matrix: tactics x techniques with detection counts and max severity."""
    if not detections:
        return _empty("No detections")
    rows: Dict[tuple, Dict[str, Any]] = {}
    for d in detections:
        key = (d["tactic"], d["technique_id"], d["technique_name"])
        r = rows.setdefault(key, {"count": 0, "sev": "INFO"})
        r["count"] += 1
        if SEV_ORDER.index(d["severity"]) < SEV_ORDER.index(r["sev"]) or r["sev"] == "INFO":
            if SEV_ORDER.index(d["severity"]) <= SEV_ORDER.index(r["sev"]):
                r["sev"] = d["severity"]
    tactics = [t for t in tactic_order if any(k[0] == t for k in rows)]
    fig = go.Figure()
    for ti, tactic in enumerate(tactics):
        techs = [(k, v) for k, v in rows.items() if k[0] == tactic]
        for yi, ((_, tid, tname), v) in enumerate(techs):
            fig.add_trace(go.Scatter(
                x=[ti], y=[yi], mode="markers+text", showlegend=False,
                marker=dict(size=46, color=SEV_COLOR[v["sev"]], symbol="square",
                            line=dict(width=1, color=SURFACE)),
                text=[tid], textfont=dict(size=9, color="#0b0b0b" if v["sev"] in ("MEDIUM",) else INK),
                hovertemplate=f"<b>{tid}</b> {tname}<br>{tactic}<br>{v['count']} detection(s) · "
                              f"{v['sev']}<extra></extra>"))
    fig.update_layout(**_layout("MITRE ATT&CK coverage", margin=dict(l=20, r=20, t=70, b=90),
                      height=max(320, 70 * max((sum(1 for k in rows if k[0] == t) for t in tactics), default=1) + 120)))
    fig.update_xaxes(tickmode="array", tickvals=list(range(len(tactics))), ticktext=tactics,
                     tickangle=-30, range=[-0.6, len(tactics) - 0.4], showgrid=False)
    fig.update_yaxes(visible=False, range=[-0.6, max((sum(1 for k in rows if k[0] == t)
                                                      for t in tactics), default=1) - 0.4])
    return fig


def attack_chain_figure(incident: Dict[str, Any]):
    """Horizontal stepped chain of an incident's stages."""
    chain = incident.get("attack_chain", [])
    if not chain:
        return _empty("No chain")
    fig = go.Figure()
    xs = list(range(len(chain)))
    for i, step in enumerate(chain):
        sev = step.get("severity", "INFO")
        fig.add_trace(go.Scatter(
            x=[i], y=[0], mode="markers+text", showlegend=False,
            marker=dict(size=40, color=SEV_COLOR.get(sev, MUTED), line=dict(width=2, color=SURFACE)),
            text=[str(step["step"])], textfont=dict(color=INK, size=13),
            customdata=[[step["technique_id"], step["technique"], step["tactic"],
                         step.get("host", ""), step.get("link_to_previous", "") or "initial access"]],
            hovertemplate="<b>%{customdata[0]} %{customdata[1]}</b><br>%{customdata[2]} · host %{customdata[3]}"
                          "<br>link: %{customdata[4]}<extra></extra>"))
        fig.add_annotation(x=i, y=-0.33, text=f"{step['tactic']}<br>{step['technique_id']}",
                           showarrow=False, font=dict(size=9, color=INK2), align="center")
    for i in range(len(chain) - 1):
        fig.add_annotation(x=i + 1, y=0, ax=i, ay=0, xref="x", yref="y", axref="x", ayref="y",
                           showarrow=True, arrowhead=2, arrowwidth=1.5, arrowcolor=MUTED)
    fig.update_layout(**_layout(f"Attack chain · {incident.get('incident_id', '')}", margin=dict(l=20, r=20, t=50, b=70), height=230))
    fig.update_xaxes(visible=False, range=[-0.5, len(chain) - 0.5])
    fig.update_yaxes(visible=False, range=[-0.7, 0.5])
    return fig


def process_tree_figure(nodes: List[Dict[str, Any]], highlight: Optional[set] = None):
    """Tidy-ish tree layout of ProcessNode dicts for one host."""
    if not nodes:
        return _empty("No process data")
    index = {n["key"]: n for n in nodes}
    children: Dict[Optional[str], List[str]] = {}
    for n in nodes:
        pk = n["parent_key"] if n["parent_key"] in index else None
        children.setdefault(pk, []).append(n["key"])
    for v in children.values():
        v.sort(key=lambda k: (index[k]["start"] or "", index[k]["pid"] or 0))
    pos: Dict[str, tuple] = {}
    counter = [0]

    def place(key, depth):
        kids = children.get(key, [])
        if not kids:
            y = counter[0]
            counter[0] += 1
        else:
            ys = [place(k, depth + 1) for k in kids]
            y = sum(ys) / len(ys)
        pos[key] = (depth, y)
        return y

    for root in children.get(None, []):
        place(root, 0)
    for n in nodes:  # orphans
        if n["key"] not in pos:
            place(n["key"], 0)

    fig = go.Figure()
    for n in nodes:
        pk = n["parent_key"]
        if pk in pos and n["key"] in pos:
            x0, y0 = pos[pk]
            x1, y1 = pos[n["key"]]
            fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", showlegend=False,
                                     line=dict(color=GRID, width=1), hoverinfo="skip"))
    xs, ys, colors, texts, custom = [], [], [], [], []
    for key, (x, y) in pos.items():
        n = index[key]
        xs.append(x)
        ys.append(y)
        flagged = bool(n["detection_ids"]) or (highlight and key in highlight)
        colors.append(SEV_COLOR.get(n["severity"], MUTED) if flagged else "#4a4a46")
        img = (n["image"] or "?").replace("/", "\\").rsplit("\\", 1)[-1]
        texts.append(img + ("*" if n.get("synthetic") else ""))
        custom.append([img, n.get("pid"), n.get("user") or "", (n.get("command_line") or "")[:160],
                       ", ".join(n["detection_ids"]) or "none"])
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text", showlegend=False,
        marker=dict(size=16, color=colors, line=dict(width=1, color=SURFACE)),
        text=texts, textposition="middle right", textfont=dict(size=10, color=INK2),
        customdata=custom,
        hovertemplate="<b>%{customdata[0]}</b> (pid %{customdata[1]})<br>user: %{customdata[2]}"
                      "<br>cmd: %{customdata[3]}<br>detections: %{customdata[4]}<extra></extra>"))
    fig.update_layout(**_layout("Process tree", margin=dict(l=10, r=10, t=46, b=10), height=max(240, 30 * counter[0] + 80)))
    fig.update_xaxes(visible=False, range=[-0.5, max(xs) + 1.5])
    fig.update_yaxes(visible=False, autorange="reversed")
    return fig


def ioc_scope_bar(iocs: List[Dict[str, Any]]):
    if not iocs:
        return _empty("No IOCs")
    df = pd.DataFrame(iocs)
    pivot = df.groupby(["Type", "malicious_context"]).size().unstack(fill_value=0)
    fig = go.Figure()
    if True in pivot.columns:
        fig.add_trace(go.Bar(name="Attack-linked", y=pivot.index, x=pivot[True], orientation="h",
                             marker_color="#d03b3b", hovertemplate="%{y}: %{x} attack-linked<extra></extra>"))
    if False in pivot.columns:
        fig.add_trace(go.Bar(name="Observed", y=pivot.index, x=pivot[False], orientation="h",
                             marker_color="#3987e5", hovertemplate="%{y}: %{x} observed<extra></extra>"))
    fig.update_layout(**_layout("IOCs by type", height=max(240, 40 * len(pivot) + 90), barmode="stack",
                      legend=dict(orientation="h", y=1.12, bgcolor="rgba(0,0,0,0)")))
    fig.update_xaxes(title="Count")
    return fig


# Backwards-compatible names used by the previous app version
def create_timeline_chart(events_df):
    return severity_timeline(events_df)


def create_risk_distribution(events_df):
    if events_df is None or events_df.empty:
        return _empty()
    counts = events_df["severity"].value_counts()
    order = [s for s in SEV_ORDER if s in counts.index]
    fig = go.Figure(go.Pie(labels=order, values=[counts[s] for s in order], hole=0.5,
                           marker=dict(colors=[SEV_COLOR[s] for s in order]),
                           textfont=dict(color=INK)))
    fig.update_layout(**_layout("Event severity distribution", height=320))
    return fig
