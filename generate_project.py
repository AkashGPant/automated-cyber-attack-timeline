import os

base_dir = r"c:\Users\AKASH\Desktop\CyberIA"

structure = {
    "requirements.txt": """streamlit>=1.32.0
pandas>=2.2.1
numpy>=1.26.4
plotly>=5.19.0
pytest>=8.1.1""",

    "README.md": """# Automated Cyber Attack Timeline Reconstruction and Forensic Analysis System

## Overview
A defensive digital-forensics application that allows investigators to upload forensic logs, parse/normalize them, correlate chronologically, and extract IOCs and MITRE ATT&CK techniques.

## Features
- File Upload for Event Logs (CSV, JSON, PCAP/CSV)
- Automated Log Parsing & Normalization
- Event Correlation Engine
- Suspicious Activity Detection
- Risk Scoring & MITRE ATT&CK Mapping
- IOC Extraction
- Cyberattack Timeline Reconstruction
- Exportable Forensic Reports

## Installation
```bash
python -m venv venv
venv\\Scripts\\activate
pip install -r requirements.txt
```

## Running the Application
```bash
python scripts/generate_sample_data.py
streamlit run app.py
```
""",

    ".gitignore": """venv/
__pycache__/
*.pyc
.env
reports_output/
.pytest_cache/""",

    "config/config.py": """import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'sample_data')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports_output')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

RISK_LOW = 30
RISK_MEDIUM = 60
RISK_HIGH = 80
""",

    "models/__init__.py": "",
    "models/event_model.py": """from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime

@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    
    host: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    file_path: Optional[str] = None
    command_line: Optional[str] = None
    domain: Optional[str] = None
    description: Optional[str] = None
    
    severity: str = "INFO"
    risk_score: int = 0
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "username": self.username,
            "process_name": self.process_name,
            "parent_process": self.parent_process,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "command_line": self.command_line,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique": self.mitre_technique
        }
""",

    "core/__init__.py": "",
    "core/normalization.py": """import pandas as pd
from typing import Any
from datetime import datetime

class NormalizationEngine:
    @staticmethod
    def parse_timestamp(ts: Any) -> datetime:
        if pd.isna(ts) or not ts:
            return datetime.min
        try:
            return pd.to_datetime(ts).to_pydatetime()
        except Exception:
            return datetime.min
""",
    
    "parsers/__init__.py": "",
    "parsers/base_parser.py": """from abc import ABC, abstractmethod
from typing import List
from models.event_model import NormalizedEvent

class BaseParser(ABC):
    @abstractmethod
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        pass
""",
    "parsers/windows_event_parser.py": """import pandas as pd
import uuid
from typing import List
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser
from core.normalization import NormalizationEngine

class WindowsEventParser(BaseParser):
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        try:
            df = pd.read_csv(file_path)
        except Exception:
            return []
            
        events = []
        for _, row in df.iterrows():
            event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=NormalizationEngine.parse_timestamp(row.get('TimeCreated')),
                source='Windows Event Log',
                event_type=str(row.get('EventID', 'Unknown')),
                host=str(row.get('Computer', '')),
                username=str(row.get('TargetUserName', row.get('SubjectUserName', ''))),
                process_name=str(row.get('NewProcessName', '')),
                parent_process=str(row.get('ParentProcessName', '')),
                command_line=str(row.get('CommandLine', '')),
                description=str(row.get('Message', '')),
                raw_data=row.to_dict()
            )
            events.append(event)
        return events
""",
    "parsers/sysmon_parser.py": """import pandas as pd
import uuid
from typing import List
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser
from core.normalization import NormalizationEngine

class SysmonParser(BaseParser):
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        try:
            df = pd.read_csv(file_path)
        except Exception:
            return []
            
        events = []
        for _, row in df.iterrows():
            event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=NormalizationEngine.parse_timestamp(row.get('UtcTime')),
                source='Sysmon',
                event_type=str(row.get('EventID', 'Unknown')),
                host=str(row.get('Computer', '')),
                username=str(row.get('User', '')),
                process_name=str(row.get('Image', '')),
                parent_process=str(row.get('ParentImage', '')),
                command_line=str(row.get('CommandLine', '')),
                source_ip=str(row.get('SourceIp', '')),
                destination_ip=str(row.get('DestinationIp', '')),
                protocol=str(row.get('Protocol', '')),
                file_path=str(row.get('TargetFilename', '')),
                raw_data=row.to_dict()
            )
            events.append(event)
        return events
""",
    "parsers/wireshark_parser.py": """import pandas as pd
import uuid
from typing import List
from models.event_model import NormalizedEvent
from parsers.base_parser import BaseParser
from core.normalization import NormalizationEngine

class WiresharkParser(BaseParser):
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        try:
            df = pd.read_csv(file_path)
        except Exception:
            return []
            
        events = []
        for _, row in df.iterrows():
            event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=NormalizationEngine.parse_timestamp(row.get('Time')),
                source='Wireshark',
                event_type='Network Traffic',
                source_ip=str(row.get('Source', '')),
                destination_ip=str(row.get('Destination', '')),
                protocol=str(row.get('Protocol', '')),
                description=str(row.get('Info', '')),
                raw_data=row.to_dict()
            )
            events.append(event)
        return events
""",
    
    "core/correlation.py": """from typing import List
from models.event_model import NormalizedEvent

class CorrelationEngine:
    def correlate(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        # Sort by timestamp to reconstruct timeline
        events.sort(key=lambda x: x.timestamp)
        return events
""",

    "detection/__init__.py": "",
    "detection/mitre_mapping.py": """MITRE_TECHNIQUES = {
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "description": "Adversaries may abuse PowerShell commands and scripts for execution."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access", "description": "Adversaries may obtain and abuse credentials of existing accounts."},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "description": "Adversaries may transfer tools or other files from an external system into a compromised environment."},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to get a listing of services listening on remote hosts."}
}
""",
    
    "detection/rules.py": """from models.event_model import NormalizedEvent
from detection.mitre_mapping import MITRE_TECHNIQUES

class DetectionRule:
    def evaluate(self, event: NormalizedEvent):
        pass

class SuspiciousPowerShellRule(DetectionRule):
    def evaluate(self, event: NormalizedEvent):
        cmd = str(event.command_line).lower()
        if 'powershell' in cmd and ('-enc' in cmd or 'hidden' in cmd or 'bypass' in cmd):
            event.severity = "HIGH"
            event.risk_score += 70
            event.mitre_technique_id = "T1059.001"
            event.mitre_technique = MITRE_TECHNIQUES["T1059.001"]["name"]
            event.mitre_tactic = MITRE_TECHNIQUES["T1059.001"]["tactic"]
            event.description = f"Suspicious PowerShell execution detected: {event.command_line}"

class FailedLoginRule(DetectionRule):
    def evaluate(self, event: NormalizedEvent):
        if event.event_type == '4625': # Windows failed login
            event.severity = "MEDIUM"
            event.risk_score += 30
            event.mitre_technique_id = "T1078"
            event.mitre_technique = MITRE_TECHNIQUES["T1078"]["name"]
            event.mitre_tactic = MITRE_TECHNIQUES["T1078"]["tactic"]
            event.description = f"Failed login attempt for user: {event.username}"

class SuspiciousNetworkConnectionRule(DetectionRule):
    def evaluate(self, event: NormalizedEvent):
        if event.source == 'Sysmon' and event.event_type == '3': # Network connection
            dest_ip = str(event.destination_ip)
            # Dummy check for external/suspicious IP
            if dest_ip.startswith("185.") or dest_ip.startswith("91."):
                event.severity = "HIGH"
                event.risk_score += 65
                event.mitre_technique_id = "T1105"
                event.mitre_technique = MITRE_TECHNIQUES["T1105"]["name"]
                event.mitre_tactic = MITRE_TECHNIQUES["T1105"]["tactic"]
                event.description = f"Outbound connection to potentially suspicious IP: {dest_ip}"
""",
    
    "detection/detector.py": """from typing import List
from models.event_model import NormalizedEvent
from detection.rules import SuspiciousPowerShellRule, FailedLoginRule, SuspiciousNetworkConnectionRule

class DetectionEngine:
    def __init__(self):
        self.rules = [
            SuspiciousPowerShellRule(),
            FailedLoginRule(),
            SuspiciousNetworkConnectionRule()
        ]
        
    def scan(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        for event in events:
            for rule in self.rules:
                rule.evaluate(event)
        return events
""",

    "core/risk_scoring.py": """from typing import List
from models.event_model import NormalizedEvent
from config.config import RISK_LOW, RISK_MEDIUM, RISK_HIGH

class RiskScoringEngine:
    def calculate_risk(self, events: List[NormalizedEvent]):
        for event in events:
            if event.risk_score == 0:
                event.severity = "INFO"
            elif event.risk_score < RISK_LOW:
                event.severity = "LOW"
            elif event.risk_score < RISK_MEDIUM:
                event.severity = "MEDIUM"
            elif event.risk_score < RISK_HIGH:
                event.severity = "HIGH"
            else:
                event.severity = "CRITICAL"
        return events
""",

    "ioc/__init__.py": "",
    "ioc/extractor.py": """import re
from typing import List, Dict, Any
from models.event_model import NormalizedEvent

class IOCExtractor:
    def __init__(self):
        self.ip_pattern = re.compile(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b')
        self.domain_pattern = re.compile(r'\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b')
        
    def extract(self, events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
        iocs = []
        seen = set()
        
        for event in events:
            if event.command_line and str(event.command_line) != 'nan':
                ips = self.ip_pattern.findall(str(event.command_line))
                for ip in ips:
                    if ip not in seen:
                        iocs.append({"IOC": ip, "Type": "IP", "Source Event ID": event.event_id})
                        seen.add(ip)
                        event.ioc_type = "IP"
                        event.ioc_value = ip
            
            if event.destination_ip and str(event.destination_ip) != 'nan':
                ip = str(event.destination_ip)
                if ip not in seen and ip != 'None' and ip != '':
                    iocs.append({"IOC": ip, "Type": "IP", "Source Event ID": event.event_id})
                    seen.add(ip)
                    
        return iocs
""",

    "reports/__init__.py": "",
    "reports/report_generator.py": """import pandas as pd
import json
import os
from typing import List
from models.event_model import NormalizedEvent
from config.config import REPORTS_DIR

class ReportGenerator:
    def generate_csv(self, events: List[NormalizedEvent], filename="forensic_report.csv") -> str:
        df = pd.DataFrame([e.to_dict() for e in events])
        path = os.path.join(REPORTS_DIR, filename)
        df.to_csv(path, index=False)
        return path
        
    def generate_json(self, events: List[NormalizedEvent], filename="forensic_report.json") -> str:
        data = [e.to_dict() for e in events]
        path = os.path.join(REPORTS_DIR, filename)
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
        return path
""",
    
    "visualization/__init__.py": "",
    "visualization/charts.py": """import plotly.express as px

def create_timeline_chart(events_df):
    if events_df.empty:
        return None
    fig = px.scatter(events_df, x="timestamp", y="severity", color="severity",
                     hover_data=["event_type", "source", "description"],
                     title="Cyber Attack Timeline",
                     color_discrete_map={
                         "INFO": "green",
                         "LOW": "blue",
                         "MEDIUM": "orange",
                         "HIGH": "red",
                         "CRITICAL": "darkred"
                     })
    return fig

def create_risk_distribution(events_df):
    if events_df.empty:
        return None
    fig = px.pie(events_df, names="severity", title="Event Severity Distribution",
                 color="severity",
                 color_discrete_map={
                     "INFO": "green",
                     "LOW": "blue",
                     "MEDIUM": "orange",
                     "HIGH": "red",
                     "CRITICAL": "darkred"
                 })
    return fig
""",

    "scripts/__init__.py": "",
    "scripts/generate_sample_data.py": """import pandas as pd
import os
from datetime import datetime, timedelta

def generate_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'sample_data')
    os.makedirs(data_dir, exist_ok=True)
    
    now = datetime.now()
    
    win_events = pd.DataFrame([
        {"TimeCreated": (now - timedelta(minutes=30)).isoformat(), "EventID": "4624", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Successful login"},
        {"TimeCreated": (now - timedelta(minutes=28)).isoformat(), "EventID": "4625", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Failed login"},
        {"TimeCreated": (now - timedelta(minutes=27)).isoformat(), "EventID": "4625", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Failed login"},
        {"TimeCreated": (now - timedelta(minutes=26)).isoformat(), "EventID": "4624", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Successful login"},
    ])
    win_events.to_csv(os.path.join(data_dir, 'windows_events.csv'), index=False)
    
    sysmon_events = pd.DataFrame([
        {"UtcTime": (now - timedelta(minutes=25)).isoformat(), "EventID": "1", "Computer": "DESKTOP-01", "User": "admin", "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc JABz...", "TargetFilename": ""},
        {"UtcTime": (now - timedelta(minutes=20)).isoformat(), "EventID": "11", "Computer": "DESKTOP-01", "User": "admin", "Image": "powershell.exe", "CommandLine": "", "TargetFilename": "C:\\\\Temp\\\\malicious.exe"},
        {"UtcTime": (now - timedelta(minutes=18)).isoformat(), "EventID": "3", "Computer": "DESKTOP-01", "User": "admin", "Image": "C:\\\\Temp\\\\malicious.exe", "SourceIp": "192.168.1.50", "DestinationIp": "185.10.10.20", "Protocol": "tcp"},
    ])
    sysmon_events.to_csv(os.path.join(data_dir, 'sysmon_events.csv'), index=False)
    
    wire_events = pd.DataFrame([
        {"Time": (now - timedelta(minutes=18)).isoformat(), "Source": "192.168.1.50", "Destination": "185.10.10.20", "Protocol": "TCP", "Info": "443 > 49152 [SYN]"}
    ])
    wire_events.to_csv(os.path.join(data_dir, 'network_events.csv'), index=False)
    
    print("Sample data generated successfully in sample_data/ directory.")

if __name__ == "__main__":
    generate_data()
""",

    "tests/__init__.py": "",
    "tests/test_parsers.py": """import pytest
from parsers.windows_event_parser import WindowsEventParser

def test_windows_parser_empty():
    parser = WindowsEventParser()
    events = parser.parse("nonexistent.csv")
    assert len(events) == 0
""",

    "app.py": """import streamlit as st
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
            st.success(f"Reports generated successfully at: \\n- {csv_path}\\n- {json_path}")
            
            with open(csv_path, "rb") as f:
                st.download_button("Download CSV Report", f, file_name="forensic_report.csv")
            with open(json_path, "rb") as f:
                st.download_button("Download JSON Report", f, file_name="forensic_report.json")
    else:
        st.warning("Please upload evidence first.")
"""
}

for path, content in structure.items():
    full_path = os.path.join(base_dir, path.replace('/', os.sep))
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)

print("Project generated successfully!")
