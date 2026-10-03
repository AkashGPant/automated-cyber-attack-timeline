# Automated Cyber Attack Timeline Reconstruction and Forensic Analysis System

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
venv\Scripts\activate
pip install -r requirements.txt
```

## Running the Application
```bash
python scripts/generate_sample_data.py
streamlit run app.py
```
