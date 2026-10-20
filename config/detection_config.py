"""Configurable detection settings.

Defaults live here. To tune without editing code, create
``config/detection_rules.json`` with any subset of these keys; it is deep-merged
over the defaults (e.g. ``{"brute_force": {"threshold": 10}}`` or
``{"lolbins": {"enabled": false}}``).
"""
from __future__ import annotations

import copy
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_RULE_CONFIG: Dict[str, Any] = {
    "global": {
        # Internal address space (RFC1918, loopback, link-local, CGNAT, ULA)
        "internal_cidrs": [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
            "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
        ],
        # Destinations never treated as C2 / exfil (e.g. vendor update / SaaS ranges)
        "allowlisted_cidrs": ["13.107.0.0/16", "20.190.128.0/18", "40.126.0.0/18"],
        "allowlisted_domains": [
            "microsoft.com", "windowsupdate.com", "office.com", "office365.com",
            "live.com", "google.com", "gstatic.com", "googleapis.com",
        ],
        "allowlisted_users": [],
        "allowlisted_hosts": [],
        # Process paths treated as trusted parents for persistence-style activity
        "trusted_process_prefixes": [
            "c:\\program files\\", "c:\\program files (x86)\\",
        ],
        "user_writable_paths": [
            "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\",
            "\\programdata\\", "\\perflogs\\", "\\windows\\tasks\\", "/tmp/", "/dev/shm/",
            "/var/tmp/",
        ],
        "watchlist_ips": [],
        "watchlist_domains": [],
    },
    "suspicious_powershell": {"enabled": True, "min_indicators": 1},
    "lolbins": {"enabled": True},
    "persistence": {"enabled": True},
    "privilege_escalation": {"enabled": True},
    "credential_access": {"enabled": True},
    "defense_evasion": {"enabled": True},
    "office_child_process": {"enabled": True},
    "ingress_tool_transfer": {"enabled": True,
                              "extensions": [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js",
                                             ".hta", ".scr", ".msi", ".cmd"]},
    "suspicious_network_connection": {"enabled": True},
    "brute_force": {"enabled": True, "threshold": 8, "window_minutes": 10,
                    "success_window_minutes": 30},
    "port_scan": {"enabled": True, "distinct_ports": 15, "distinct_hosts": 20,
                  "window_seconds": 120},
    "beaconing": {"enabled": True, "min_connections": 8, "max_jitter_ratio": 0.2,
                  "min_interval_seconds": 5, "max_interval_seconds": 3600},
    "exfiltration": {"enabled": True, "bytes_threshold": 10_000_000, "window_minutes": 60},
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_rule_config(path: Optional[str] = None,
                     overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return defaults merged with an optional JSON file and explicit overrides."""
    cfg = copy.deepcopy(DEFAULT_RULE_CONFIG)
    if path is None:
        from config.config import RULES_OVERRIDE_FILE
        path = RULES_OVERRIDE_FILE
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                _deep_merge(cfg, json.load(fh))
        except (OSError, ValueError) as exc:
            logger.warning("Ignoring invalid rule config %s: %s", path, exc)
    if overrides:
        _deep_merge(cfg, copy.deepcopy(overrides))
    return cfg
