import streamlit as st
import pandas as pd
import os
from parsers.windows_event_parser import WindowsEventParser
from parsers.sysmon_parser import SysmonParser
from parsers.wireshark_parser import WiresharkParser
from core.correlation import CorrelationEngine
from core.risk_scoring import RiskScoringEngine
from detection.detector import DetectionEngine
from ioc.extractor import IOCExtractor
from reports.report_generator import ReportGenerator
from visualization.charts import create_timeline_chart, create_risk_distribution
from config.config import DATA_DIR

st.set_page_config(page_title="Cyber Attack Timeline Reconstruction", layout="wide")

st.title("Automated Cyber Attack Timeline Reconstruction")
st.markdown("Upload forensic logs to automatically parse, normalize, correlate, and analyze for suspicious activities.")

menu = ["Dashboard", "Upload Evidence", "Timeline Analysis", "IOC & MITRE Mapping", "Forensic Report"]
choice = st.sidebar.selectbox("Navigation", menu)

@st.cache_data
def process_data(file_paths):
    all_events = []
    
    win_parser = WindowsEventParser()
    sysmon_parser = SysmonParser()
    wire_parser = WiresharkParser()
    
    for temp_path in file_paths:
        if 'windows' in temp_path.lower():
            all_events.extend(win_parser.parse(temp_path))
        elif 'sysmon' in temp_path.lower():
            all_events.extend(sysmon_parser.parse(temp_path))
        elif 'network' in temp_path.lower() or 'pcap' in temp_path.lower():
            all_events.extend(wire_parser.parse(temp_path))
        else:
            all_events.extend(win_parser.parse(temp_path))
            
    # Processing pipeline
    events = CorrelationEngine().correlate(all_events)
    events = DetectionEngine().scan(events)
    events = RiskScoringEngine().calculate_risk(events)
    iocs = IOCExtractor().extract(events)
    
    return events, iocs

if choice == "Dashboard":
    st.header("Overview")
    st.info("Navigate to 'Upload Evidence' to begin analysis, or view the Timeline if data is loaded.")
    if 'events' in st.session_state:
        st.metric("Total Events Processed", len(st.session_state['events']))
        st.metric("Total IOCs Detected", len(st.session_state['iocs']))
    
elif choice == "Upload Evidence":
    st.header("Upload Forensic Logs")
    st.write("Supported formats: CSV exports of Windows Event Logs, Sysmon, Wireshark.")
    
    if st.button("Load Sample Dataset"):
        sample_files = [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR) if f.endswith('.csv')]
        if not sample_files:
            st.error("Sample data not found. Please run scripts/generate_sample_data.py first.")
        else:
            events, iocs = process_data(sample_files)
            st.session_state['events'] = events
            st.session_state['iocs'] = iocs
            st.success(f"Sample dataset loaded successfully! Found {len(events)} events.")
        
    uploaded_files = st.file_uploader("Upload CSV files", type=["csv"], accept_multiple_files=True)
    if uploaded_files:
        file_paths = []
        for uploaded_file in uploaded_files:
            temp_path = os.path.join(DATA_DIR, uploaded_file.name)
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            file_paths.append(temp_path)
            
        with st.spinner("Processing files..."):
            events, iocs = process_data(file_paths)
            st.session_state['events'] = events
            st.session_state['iocs'] = iocs
            st.success(f"Processed {len(events)} events successfully!")

elif choice == "Timeline Analysis":
    st.header("Cyberattack Timeline")
    if 'events' in st.session_state and st.session_state['events']:
        events = st.session_state['events']
        df = pd.DataFrame([e.to_dict() for e in events])
        
        col1, col2 = st.columns(2)
        with col1:
            fig1 = create_timeline_chart(df)
            if fig1: st.plotly_chart(fig1, use_container_width=True)
        with col2:
            fig2 = create_risk_distribution(df)
            if fig2: st.plotly_chart(fig2, use_container_width=True)
            
        st.subheader("Event Details")
        st.dataframe(df[["timestamp", "source", "event_type", "severity", "description", "mitre_technique_id"]])
    else:
        st.warning("Please upload evidence first.")

elif choice == "IOC & MITRE Mapping":
    st.header("Indicators of Compromise & MITRE ATT&CK")
    if 'events' in st.session_state and 'iocs' in st.session_state:
        st.subheader("Extracted IOCs")
        st.dataframe(pd.DataFrame(st.session_state['iocs']))
        
        st.subheader("MITRE ATT&CK Mapping")
        mitre_events = [e.to_dict() for e in st.session_state['events'] if e.mitre_technique_id]
        if mitre_events:
            st.dataframe(pd.DataFrame(mitre_events)[["timestamp", "source", "severity", "mitre_technique_id", "description"]])
        else:
            st.info("No MITRE techniques mapped based on available evidence.")
    else:
        st.warning("Please upload evidence first.")

elif choice == "Forensic Report":
    st.header("Generate Forensic Report")
    if 'events' in st.session_state:
        if st.button("Generate CSV & JSON Reports"):
            generator = ReportGenerator()
            csv_path = generator.generate_csv(st.session_state['events'])
            json_path = generator.generate_json(st.session_state['events'])
            st.success(f"Reports generated successfully at: \n- {csv_path}\n- {json_path}")
            
            with open(csv_path, "rb") as f:
                st.download_button("Download CSV Report", f, file_name="forensic_report.csv")
            with open(json_path, "rb") as f:
                st.download_button("Download JSON Report", f, file_name="forensic_report.json")
    else:
        st.warning("Please upload evidence first.")
