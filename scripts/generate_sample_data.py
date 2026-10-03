import pandas as pd
import os
from datetime import datetime, timedelta

def generate_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'sample_data')
    os.makedirs(data_dir, exist_ok=True)
    
    now = datetime.now()
    
    win_events = pd.DataFrame([
        {"TimeCreated": (now - timedelta(minutes=30)).isoformat(), "EventID": "4624", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Successful login"},
        {"TimeCreated": (now - timedelta(minutes=28)).isoformat(), "EventID": "4625", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Failed login"},
        {"TimeCreated": (now - timedelta(minutes=27)).isoformat(), "EventID": "4625", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Failed login"},
        {"TimeCreated": (now - timedelta(minutes=26)).isoformat(), "EventID": "4624", "Computer": "DESKTOP-01", "TargetUserName": "admin", "Message": "Successful login"},
    ])
    win_events.to_csv(os.path.join(data_dir, 'windows_events.csv'), index=False)
    
    sysmon_events = pd.DataFrame([
        {"UtcTime": (now - timedelta(minutes=25)).isoformat(), "EventID": "1", "Computer": "DESKTOP-01", "User": "admin", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc JABz...", "TargetFilename": ""},
        {"UtcTime": (now - timedelta(minutes=20)).isoformat(), "EventID": "11", "Computer": "DESKTOP-01", "User": "admin", "Image": "powershell.exe", "CommandLine": "", "TargetFilename": "C:\\Temp\\malicious.exe"},
        {"UtcTime": (now - timedelta(minutes=18)).isoformat(), "EventID": "3", "Computer": "DESKTOP-01", "User": "admin", "Image": "C:\\Temp\\malicious.exe", "SourceIp": "192.168.1.50", "DestinationIp": "185.10.10.20", "Protocol": "tcp"},
    ])
    sysmon_events.to_csv(os.path.join(data_dir, 'sysmon_events.csv'), index=False)
    
    wire_events = pd.DataFrame([
        {"Time": (now - timedelta(minutes=18)).isoformat(), "Source": "192.168.1.50", "Destination": "185.10.10.20", "Protocol": "TCP", "Info": "443 > 49152 [SYN]"}
    ])
    wire_events.to_csv(os.path.join(data_dir, 'network_events.csv'), index=False)
    
    print("Sample data generated successfully in sample_data/ directory.")

if __name__ == "__main__":
    generate_data()
