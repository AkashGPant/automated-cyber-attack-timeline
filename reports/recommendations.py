"""Response recommendations keyed by ATT&CK technique prefix."""
from typing import Iterable, List

RECOMMENDATIONS = {
    "T1595": "Review perimeter exposure; block the scanning source at the edge firewall and confirm only required services are internet-facing.",
    "T1046": "Investigate the internal scanning host for compromise; restrict east-west traffic with host firewalls/segmentation.",
    "T1110": "Lock or reset the targeted accounts, enforce MFA and account-lockout policy, and block the offending source IPs.",
    "T1078": "Reset credentials for the compromised account, revoke active sessions/tokens and review all activity performed by it.",
    "T1133": "Restrict remote access (RDP/VPN) to MFA-protected gateways; never expose RDP directly to the internet.",
    "T1059.001": "Collect and decode the PowerShell payload; enable Script Block and Module logging, Constrained Language Mode and AMSI.",
    "T1059": "Review the spawned shell commands and their parent processes; restrict interpreter use via application control.",
    "T1204": "Quarantine the malicious document/email, search mailboxes for the same lure and block Office child processes via ASR rules.",
    "T1218": "Block or alert on proxy-execution LOLBins with WDAC/ASR rules; retrieve any remote payload referenced on the command line.",
    "T1127": "Restrict MSBuild execution to developer systems via application control.",
    "T1197": "Enumerate and remove BITS jobs (bitsadmin /list /allusers /verbose) and recover transferred files.",
    "T1047": "Review WMI command execution and permanent event subscriptions; restrict remote WMI.",
    "T1140": "Recover and analyze the decoded file; hash and sweep the environment for it.",
    "T1105": "Acquire the dropped payload, hash it, sweep endpoints for the hash and block the download source.",
    "T1547": "Remove the autorun entry, acquire the referenced binary and verify no further Run keys/Startup items exist.",
    "T1053": "Delete the malicious scheduled task, export its XML for evidence and audit all tasks on affected hosts.",
    "T1543": "Stop and delete the malicious service; acquire the service binary for analysis.",
    "T1136": "Disable/delete the unauthorized account and audit account-creation rights.",
    "T1098": "Remove the account from privileged groups, review group changes and enforce tiered admin model / PAM.",
    "T1548": "Set UAC to 'Always notify', remove the hijacked registry keys and restrict local admin rights.",
    "T1003": "Assume credential theft: reset affected passwords (including krbtgt twice if DC involved), enable LSA protection / Credential Guard.",
    "T1070": "Treat log clearing as confirmed compromise; recover logs from SIEM/forwarders and enable log forwarding with tamper protection.",
    "T1562": "Re-enable and enforce Defender settings via policy; enable tamper protection.",
    "T1490": "Isolate immediately (ransomware precursor); protect backups offline and verify shadow copy integrity.",
    "T1071": "Block the C2 destination at proxy/firewall/DNS, isolate the beaconing host and capture memory before remediation.",
    "T1571": "Block outbound traffic on non-standard ports by default; investigate the connecting process.",
    "T1560": "Locate the staged archive, identify its contents and determine what data was collected.",
    "T1041": "Block the C2 channel, quantify data loss from network logs and start breach-notification assessment.",
    "T1048": "Block the destination, quantify transferred data and review DLP / egress controls.",
    "T1567": "Revoke cloud-storage tokens used by the tool, block the service for non-approved users and quantify uploaded data.",
}

GENERAL = {
    "CRITICAL": "Isolate affected hosts from the network now, preserve memory and disk images, and escalate to incident response.",
    "HIGH": "Contain affected hosts/accounts within hours and begin full forensic triage.",
    "MEDIUM": "Validate the activity with the asset owner and monitor closely for escalation.",
    "LOW": "Review during normal triage; tune the rule if the activity is confirmed benign.",
}


def recommendations_for(technique_ids: Iterable[str], severity: str = "") -> List[str]:
    out: List[str] = []
    if severity in GENERAL:
        out.append(GENERAL[severity])
    for tid in technique_ids:
        for prefix in (tid, tid.split(".")[0]):
            rec = RECOMMENDATIONS.get(prefix)
            if rec and rec not in out:
                out.append(rec)
                break
    return out
