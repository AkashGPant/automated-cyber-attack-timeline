import re
from typing import List, Dict, Any
from models.event_model import NormalizedEvent

class IOCExtractor:
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        
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
