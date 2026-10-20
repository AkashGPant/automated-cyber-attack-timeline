"""MITRE ATT&CK (Enterprise) techniques used by the detection rules.

``tactic`` keeps the original comma-separated string; ``tactics`` is the
ordered list (first entry = default tactic for kill-chain ordering).
"""

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

_T = {
    "T1595": ("Active Scanning", ["Reconnaissance"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["Credential Access"]),
    "T1110.003": ("Brute Force: Password Spraying", ["Credential Access"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Defense Evasion", "Persistence", "Privilege Escalation"]),
    "T1133": ("External Remote Services", ["Initial Access", "Persistence"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1059.003": ("Windows Command Shell", ["Execution"]),
    "T1047": ("Windows Management Instrumentation", ["Execution"]),
    "T1204.002": ("User Execution: Malicious File", ["Execution"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["Persistence", "Execution", "Privilege Escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1136.001": ("Create Account: Local Account", ["Persistence"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1548.002": ("Abuse Elevation Control Mechanism: Bypass UAC", ["Privilege Escalation", "Defense Evasion"]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["Credential Access"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["Defense Evasion"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["Defense Evasion"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["Defense Evasion"]),
    "T1197": ("BITS Jobs", ["Defense Evasion", "Persistence"]),
    "T1218.004": ("System Binary Proxy Execution: InstallUtil", ["Defense Evasion"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["Defense Evasion"]),
    "T1218.007": ("System Binary Proxy Execution: Msiexec", ["Defense Evasion"]),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["Defense Evasion"]),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ["Defense Evasion"]),
    "T1127.001": ("Trusted Developer Utilities Proxy Execution: MSBuild", ["Defense Evasion"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1071": ("Application Layer Protocol", ["Command and Control"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["Command and Control"]),
    "T1571": ("Non-Standard Port", ["Command and Control"]),
    "T1560.001": ("Archive Collected Data: Archive via Utility", ["Collection"]),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Exfiltration"]),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage", ["Exfiltration"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
}

MITRE_TECHNIQUES = {
    tid: {
        "name": name,
        "tactic": ", ".join(tactics),
        "tactics": tactics,
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }
    for tid, (name, tactics) in _T.items()
}

# Original descriptive text kept for the techniques that existed before.
MITRE_TECHNIQUES["T1059.001"]["description"] = "Adversaries may abuse PowerShell commands and scripts for execution."
MITRE_TECHNIQUES["T1078"]["description"] = "Adversaries may obtain and abuse credentials of existing accounts."
MITRE_TECHNIQUES["T1105"]["description"] = "Adversaries may transfer tools or other files from an external system into a compromised environment."
MITRE_TECHNIQUES["T1046"]["description"] = "Adversaries may attempt to get a listing of services listening on remote hosts."


def technique(tid: str) -> dict:
    return MITRE_TECHNIQUES.get(tid, {"name": tid, "tactic": "Unknown", "tactics": ["Unknown"], "url": ""})


def tactic_rank(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)
