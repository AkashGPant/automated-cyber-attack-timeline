import os
import tempfile

import pytest

from parsers.router import detect_parser, parse_file
from parsers.sysmon_parser import SysmonParser
from parsers.windows_event_parser import WindowsEventParser
from parsers.wireshark_parser import WiresharkParser


def _write(tmp_path, name, content):
    p = os.path.join(tmp_path, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


def test_windows_parser_missing_file():
    assert WindowsEventParser().parse("nonexistent.csv") == []


def test_empty_file(tmp_path):
    p = _write(tmp_path, "empty.csv", "")
    parser = WindowsEventParser()
    assert parser.parse(p) == []
    assert parser.errors


def test_missing_required_columns(tmp_path):
    p = _write(tmp_path, "foo.csv", "Col1,Col2\n1,2\n")
    parser = SysmonParser()
    assert parser.parse(p) == []
    assert any("missing required" in e for e in parser.errors)


def test_sysmon_parse_and_alias(tmp_path):
    p = _write(tmp_path, "sysmon.csv",
               "UtcTime,Event ID,Computer,User,Image,CommandLine,ParentImage,ProcessId\n"
               "2026-10-18 09:00:00.000,1,HOST1,CORP\\u,C:\\Windows\\System32\\cmd.exe,cmd.exe,explorer.exe,1234\n")
    events = SysmonParser().parse(p)
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "1" and e.host == "HOST1" and e.process_id == 1234
    assert e.source_file == "sysmon.csv" and e.row_number == 2


def test_bad_timestamp_row_skipped(tmp_path):
    p = _write(tmp_path, "sysmon.csv",
               "UtcTime,EventID,Computer,Image\n"
               "not-a-date,1,HOST1,cmd.exe\n2026-10-18 09:00:00,1,HOST1,cmd.exe\n")
    parser = SysmonParser()
    events = parser.parse(p)
    assert len(events) == 1 and parser.rows_skipped == 1


def test_wireshark_ports_from_info(tmp_path):
    p = _write(tmp_path, "network.csv",
               "Time,Source,Destination,Protocol,Info\n"
               "2026-10-18 09:00:00.0,10.0.0.1,203.0.113.5,TCP,51234 > 443 [SYN] Seq=0\n")
    e = WiresharkParser().parse(p)[0]
    assert e.destination_port == 443 and e.source_port == 51234


def test_detect_parser_by_header(tmp_path):
    sp = _write(tmp_path, "logA.csv", "UtcTime,Image,ParentImage\n2026-01-01,cmd,explorer\n")
    wp = _write(tmp_path, "logB.csv", "TimeCreated,TargetUserName,LogonType\n2026-01-01,u,2\n")
    np = _write(tmp_path, "logC.csv", "Time,Source,Destination,Info\n2026-01-01,1.1.1.1,2.2.2.2,x\n")
    assert isinstance(detect_parser(sp), SysmonParser)
    assert isinstance(detect_parser(wp), WindowsEventParser)
    assert isinstance(detect_parser(np), WiresharkParser)


def test_unrecognised_format(tmp_path):
    p = _write(tmp_path, "mystery.csv", "a,b,c\n1,2,3\n")
    events, report = parse_file(p)
    assert events == [] and report.parser is None and report.errors
