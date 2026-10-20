# CyberIA — Automated Cyberattack Timeline Reconstruction & Forensic Analysis

A defensive, offline DFIR system that ingests forensic logs (Windows Event Log,
Sysmon, Wireshark CSV exports), reconstructs attack timelines and process trees,
runs a configurable detection engine mapped to MITRE ATT&CK, extracts and scopes
IOCs, scores risk with explanations, and produces forensic reports — all in a
dark-themed Streamlit SOC console.

## Features
- **Parsing & normalization** — robust CSV loading (encoding/aliases/bad-line
  tolerant), UTC timestamp normalization, per-row error isolation, source
  auto-detection from headers.
- **Correlation** — chronological timeline, IP→host enrichment, process-tree
  reconstruction (PID/PPID), and incident grouping with attack-chain
  reconstruction (brute force → logon → PowerShell → C2, etc.).
- **Detection engine** — configurable rules (privilege escalation, persistence,
  LOLBins, credential access, defense evasion, port scanning, C2 beaconing,
  exfiltration, …) with severity, confidence and evidence; low false positives
  via allowlists and behavioural thresholds. See `config/detection_config.py`;
  override with `config/detection_rules.json`.
- **IOC extraction** — IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256, suspicious
  file paths; deduplicated, scoped (internal/external/allowlisted) and associated
  with events and detections.
- **Explainable risk scoring** — 0–100 at event/detection/incident level, with
  no double-counting and a written rationale.
- **Forensic reports** — JSON + CSV (incidents, chains, detections, IOCs, events)
  and a ZIP bundle, with executive summary, MITRE mappings, evidence references
  and recommendations.

## Install
```bash
python -m venv venv
venv\Scripts\activate          # Windows  (source venv/bin/activate on *nix)
pip install -r requirements.txt
```

## Run
```bash
python scripts/generate_sample_data.py     # creates synthetic multi-stage dataset
streamlit run app.py
```
Load the sample dataset from the sidebar, or upload your own CSV log exports.

## Tests
```bash
pytest -q
```

## Architecture
```
parsers/   → router + per-source parsers      core/      → normalization, correlation,
models/    → NormalizedEvent, Detection, …               risk scoring, pipeline
detection/ → rules, detector, MITRE mapping   ioc/       → IOC extraction
reports/   → report generator, recommendations visualization/ → Plotly SOC charts
config/    → paths + detection configuration  app.py     → Streamlit SOC console
```
`core/pipeline.py` wires the stages: parse → correlate → detect → IOCs →
incidents/chains → risk scoring.

All processing is local; no database, external APIs or network calls are used.
