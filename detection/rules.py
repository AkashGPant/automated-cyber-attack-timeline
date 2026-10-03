from models.event_model import NormalizedEvent
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
