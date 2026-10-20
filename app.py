from __future__ import annotations

import os
import tempfile

import pandas as pd
import streamlit as st

from config.config import DATA_DIR
from config.detection_config import load_rule_config
from core.pipeline import analyze_files
from detection.mitre_mapping import TACTIC_ORDER
from reports.recommendations import recommendations_for
from reports.report_generator import ReportGenerator
from visualization import charts

st.set_page_config(page_title="CyberIA SOC Console", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

DARK_CSS = """
<style>
.stApp { background:#0d0d0d; color:#f0efec; }
section[data-testid="stSidebar"] { background:#131312; border-right:1px solid #2c2c2a; }
h1,h2,h3,h4 { color:#f0efec !important; }
.block-container { padding-top:1.4rem; }
div[data-testid="stMetric"] { background:#1a1a19; border:1px solid #2c2c2a; border-radius:10px;
  padding:14px 16px; }
div[data-testid="stMetricValue"] { font-size:1.6rem; }
.stTabs [data-baseweb="tab-list"] { gap:4px; }
.stTabs [data-baseweb="tab"] { background:#1a1a19; border-radius:8px 8px 0 0; padding:6px 14px; }
.stTabs [aria-selected="true"] { background:#242421; }
.cia-pill { display:inline-block; padding:2px 10px; border-radius:12px; font-size:.75rem;
  font-weight:600; color:#0d0d0d; }
.cia-card { background:#1a1a19; border:1px solid #2c2c2a; border-left-width:4px; border-radius:10px;
  padding:14px 18px; margin-bottom:12px; }
code { color:#e0b36b; }
</style>
"""
st.markdown(DARK_CSS, unsafe_allow_html=True)

SEV_HEX = charts.SEV_COLOR


def pill(text, sev):
    return f'<span class="cia-pill" style="background:{SEV_HEX.get(sev, "#898781")}">{text}</span>'


def card(inner, sev):
    st.markdown(f'<div class="cia-card" style="border-left-color:{SEV_HEX.get(sev, "#898781")}">{inner}</div>',
                unsafe_allow_html=True)


@st.cache_data(show_spinner=False)
def run_analysis(paths, config_sig):
    result = analyze_files(paths, load_rule_config())
    return result


def get_result():
    return st.session_state.get("result")


# --------------------------------------------------------------------------- sidebar
st.sidebar.title("🛡️ CyberIA")
st.sidebar.caption("DFIR timeline reconstruction & detection")
page = st.sidebar.radio("View", ["Overview", "Incidents & Chains", "Timeline", "Process Trees",
                                 "MITRE ATT&CK", "IOCs", "Evidence & Reports"], label_visibility="collapsed")
st.sidebar.divider()

with st.sidebar.expander("Load evidence", expanded=get_result() is None):
    if st.button("▶ Load sample dataset", use_container_width=True):
        sample = [os.path.join(DATA_DIR, f) for f in sorted(os.listdir(DATA_DIR))
                  if f.endswith(".csv")] if os.path.isdir(DATA_DIR) else []
        if not sample:
            st.error("No sample data. Run scripts/generate_sample_data.py")
        else:
            with st.spinner("Analyzing…"):
                st.session_state["result"] = run_analysis(tuple(sample), "default")
            st.rerun()
    uploaded = st.file_uploader("Upload log CSVs", type=["csv"], accept_multiple_files=True)
    if uploaded and st.button("Analyze uploads", use_container_width=True):
        tmp = tempfile.mkdtemp(prefix="cyberia_")
        paths = []
        for uf in uploaded:
            p = os.path.join(tmp, uf.name)
            with open(p, "wb") as fh:
                fh.write(uf.getbuffer())
            paths.append(p)
        with st.spinner("Analyzing…"):
            st.session_state["result"] = run_analysis(tuple(paths), "upload")
        st.rerun()

result = get_result()
if result:
    s = result.summary
    st.sidebar.divider()
    st.sidebar.metric("Overall risk", f"{s['overall_risk_score']}/100", s["overall_severity"])
    st.sidebar.caption(f"{s['total_events']} events · {s['total_detections']} detections · "
                       f"{s['total_incidents']} incidents")

if not result:
    st.title("CyberIA — SOC Console")
    st.markdown("Automated cyberattack **timeline reconstruction**, **detection** and "
                "**forensic reporting**. Load the sample dataset or upload Windows Event Log, "
                "Sysmon, or Wireshark CSV exports from the sidebar to begin.")
    st.stop()

det_dicts = [d.to_dict() for d in result.detections]


# --------------------------------------------------------------------------- Overview
if page == "Overview":
    st.title("Overview")
    c = st.columns(5)
    c[0].metric("Risk score", f"{s['overall_risk_score']}/100", s["overall_severity"])
    c[1].metric("Incidents", s["total_incidents"])
    c[2].metric("Detections", s["total_detections"])
    c[3].metric("Affected hosts", len(s["affected_hosts"]))
    c[4].metric("Malicious IOCs", s["malicious_iocs"])
    st.markdown(f"> {result.summary.get('narrative', ReportGenerator().narrative(result))}")

    left, right = st.columns([3, 2])
    with left:
        st.plotly_chart(charts.severity_timeline(pd.DataFrame([e.to_dict() for e in result.events])),
                        use_container_width=True)
    with right:
        st.plotly_chart(charts.severity_bar(det_dicts), use_container_width=True)
    a, b = st.columns(2)
    a.plotly_chart(charts.tactic_bar(det_dicts), use_container_width=True)
    b.plotly_chart(charts.ioc_scope_bar(result.iocs), use_container_width=True)

    st.subheader("Top incidents")
    for inc in sorted(result.incidents, key=lambda i: i.score, reverse=True)[:5]:
        card(f"{pill(inc.severity + ' · ' + str(inc.score), inc.severity)} "
             f"<b>{inc.incident_id} — {inc.title}</b><br>"
             f"<span style='color:#c3c2b7'>{', '.join(inc.hosts) or 'network'} · "
             f"{' → '.join(inc.tactics)} · {inc.start:%Y-%m-%d %H:%M}–{inc.end:%H:%M} UTC</span>",
             inc.severity)

# --------------------------------------------------------------------------- Incidents
elif page == "Incidents & Chains":
    st.title("Incidents & attack chains")
    if not result.incidents:
        st.info("No incidents identified.")
    for inc in sorted(result.incidents, key=lambda i: i.score, reverse=True):
        with st.expander(f"{inc.incident_id} — {inc.title}  ·  {inc.severity} ({inc.score})",
                         expanded=inc.score >= 80):
            m = st.columns(4)
            m[0].metric("Risk", f"{inc.score}/100", inc.severity)
            m[1].metric("Hosts", ", ".join(inc.hosts) or "—")
            m[2].metric("Users", ", ".join(inc.users) or "—")
            m[3].metric("Window", f"{(inc.end - inc.start).total_seconds() / 60:.0f} min")
            if inc.patterns:
                st.markdown("**Matched patterns:** " + ", ".join(inc.patterns))
            st.plotly_chart(charts.attack_chain_figure(inc.to_dict()),
                            use_container_width=True, key=f"chain_{inc.incident_id}")
            st.markdown("**Chain steps**")
            for step in inc.chain:
                link = step["link_to_previous"] or "entry point"
                st.markdown(f"{step['step']}. {pill(step['severity'], step['severity'])} "
                            f"**{step['tactic']} / {step['technique_id']}** {step['technique']} "
                            f"— {step['description']}  \n<span style='color:#898781'>↳ linked by: {link}</span>",
                            unsafe_allow_html=True)
            st.markdown("**Why this score**")
            st.caption(" · ".join(inc.score_explanation))
            if inc.iocs:
                st.markdown("**Infrastructure IOCs:** " + ", ".join(f"`{i}`" for i in inc.iocs))
            recs = recommendations_for(inc.techniques, inc.severity)
            if recs:
                st.markdown("**Recommended actions**")
                for rrec in recs:
                    st.markdown(f"- {rrec}")

# --------------------------------------------------------------------------- Timeline
elif page == "Timeline":
    st.title("Timeline")
    df = pd.DataFrame([e.to_dict() for e in result.events])
    f = st.columns(4)
    hosts = sorted({e.host for e in result.events if e.host})
    sources = sorted({e.source for e in result.events})
    sel_host = f[0].multiselect("Host", hosts, default=hosts)
    sel_src = f[1].multiselect("Source", sources, default=sources)
    sel_sev = f[2].multiselect("Severity", charts.SEV_ORDER, default=charts.SEV_ORDER)
    only_flagged = f[3].checkbox("Detections only", value=True)
    query = st.text_input("Search (process, command, IP, user, description)")

    view = df.copy()
    view = view[view["host"].isin(sel_host) & view["source"].isin(sel_src) & view["severity"].isin(sel_sev)]
    if only_flagged:
        view = view[view["rules"].astype(str).str.len() > 0]
    if query:
        q = query.lower()
        hay = view.astype(str).apply(lambda r: " ".join(r.values).lower(), axis=1)
        view = view[hay.str.contains(q, regex=False)]
    st.plotly_chart(charts.severity_timeline(view), use_container_width=True)
    st.caption(f"{len(view)} events")
    cols = ["timestamp", "severity", "source", "host", "username", "event_type", "process_name",
            "description", "mitre_technique_id", "rules", "incident_id"]
    st.dataframe(view[[c for c in cols if c in view.columns]], use_container_width=True, height=440,
                 hide_index=True)

# --------------------------------------------------------------------------- Process trees
elif page == "Process Trees":
    st.title("Process trees")
    trees = {h: n for h, n in result.process_trees.items()}
    hosts = [h for h in trees if any(nn.detection_ids for nn in trees[h])] or list(trees)
    if not hosts:
        st.info("No process-creation events to build trees from.")
    else:
        host = st.selectbox("Host", hosts)
        nodes = [n.to_dict() for n in trees[host]]
        st.plotly_chart(charts.process_tree_figure(nodes), use_container_width=True)
        st.caption("Red/orange nodes carry detections. Nodes marked * are inferred parents. "
                   "Hover for command line and PID.")

# --------------------------------------------------------------------------- MITRE
elif page == "MITRE ATT&CK":
    st.title("MITRE ATT&CK coverage")
    st.plotly_chart(charts.mitre_matrix(det_dicts, TACTIC_ORDER), use_container_width=True)
    rows = []
    for tid in sorted({d["technique_id"] for d in det_dicts}):
        ds = [d for d in det_dicts if d["technique_id"] == tid]
        rows.append({"Technique": tid, "Name": ds[0]["technique_name"], "Tactic": ds[0]["tactic"],
                     "Detections": len(ds),
                     "Max severity": max((d["severity"] for d in ds), key=charts.SEV_ORDER[::-1].index),
                     "Hosts": ", ".join(sorted({d["host"] for d in ds if d["host"]}))})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------- IOCs
elif page == "IOCs":
    st.title("Indicators of Compromise")
    st.plotly_chart(charts.ioc_scope_bar(result.iocs), use_container_width=True)
    df = pd.DataFrame(result.iocs)
    if df.empty:
        st.info("No IOCs extracted.")
    else:
        df = df.copy()
        df["first_seen"] = pd.to_datetime(df["first_seen"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        df["last_seen"] = pd.to_datetime(df["last_seen"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        c = st.columns(3)
        types = sorted(df["Type"].unique())
        sel_t = c[0].multiselect("Type", types, default=types)
        only_mal = c[1].checkbox("Attack-linked only", value=False)
        q = c[2].text_input("Search IOC")
        view = df[df["Type"].isin(sel_t)]
        if only_mal:
            view = view[view["malicious_context"]]
        if q:
            view = view[view["IOC"].str.contains(q, case=False, regex=False)]
        show = view[["IOC", "Type", "scope", "malicious_context", "count", "first_seen", "last_seen",
                     "hosts", "techniques", "rules"]].rename(
            columns={"malicious_context": "attack_linked", "count": "hits"})
        st.dataframe(show, use_container_width=True, height=460, hide_index=True)
        st.download_button("Download IOCs (CSV)", view.to_csv(index=False).encode(),
                           "cyberia_iocs.csv", "text/csv")

# --------------------------------------------------------------------------- Reports
elif page == "Evidence & Reports":
    st.title("Evidence & forensic reports")
    st.subheader("Parsed evidence")
    rep_rows = [{"File": p.file, "Parser": p.parser or "unrecognised", "Events": p.events,
                 "Rows read": p.rows_read, "Rows skipped": p.rows_skipped,
                 "Errors": len(p.errors), "Warnings": len(p.warnings)} for p in result.parse_reports]
    if rep_rows:
        st.dataframe(pd.DataFrame(rep_rows), use_container_width=True, hide_index=True)
    for p in result.parse_reports:
        for e in p.errors:
            st.error(e)
        for w in p.warnings:
            st.warning(w)
    for err in result.rule_errors:
        st.warning(err)

    st.subheader("Download reports")
    gen = ReportGenerator()
    c = st.columns(3)
    c[0].download_button("📦 Full bundle (ZIP)", gen.build_zip(result),
                         "cyberia_report.zip", "application/zip", use_container_width=True)
    import json as _json
    c[1].download_button("🧾 Report (JSON)",
                         _json.dumps(gen.build_report(result), indent=2, default=str).encode(),
                         "cyberia_report.json", "application/json", use_container_width=True)
    tables = gen.tables(result)
    c[2].download_button("📄 Incidents (CSV)", tables["incidents"].to_csv(index=False).encode(),
                         "cyberia_incidents.csv", "text/csv", use_container_width=True)
    with st.expander("Executive summary"):
        st.json(gen.build_report(result)["executive_summary"])
