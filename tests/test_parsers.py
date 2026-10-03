import pytest
from parsers.windows_event_parser import WindowsEventParser

def test_windows_parser_empty():
    parser = WindowsEventParser()
    events = parser.parse("nonexistent.csv")
    assert len(events) == 0
