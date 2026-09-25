"""Synthetic attack-campaign log generator.

Simulates "APT-DEMO": phishing -> execution -> persistence -> privesc ->
lateral movement -> exfiltration, interleaved with benign noise, across
three sources: okta, sysmon, firewall.

Stream mode (default) replays the ~30 min campaign compressed by --speed.
Burst mode writes everything immediately.

Run: python generator/campaign.py --speed 60
"""

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

LOG_DIR = os.getenv("LOG_DIR", "data/logs")

# (offset_sec, source, host, user, raw)
CAMPAIGN = [
    (0, "okta", None, "alice", {
        "eventType": "user.session.start",
        "actor": {"alternateId": "alice@corp.local"},
        "client": {"ipAddress": "185.220.101.4", "geographicalContext": {"country": "RU", "city": "Moscow"}},
        "outcome": {"result": "SUCCESS"},
        "displayMessage": "User login to Okta",
    }),
    (60, "sysmon", "WS-104", "alice", {
        "EventID": 1, "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "WINWORD.EXE /n \"invoice_2024.docm\"",
        "ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\alice", "Computer": "WS-104",
    }),
    (90, "sysmon", "WS-104", "alice", {
        "EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "User": "CORP\\alice", "Computer": "WS-104",
    }),
    (240, "sysmon", "WS-104", "alice", {
        "EventID": 13, "EventType": "SetValue",
        "TargetObject": "HKU\\S-1-5-21\\...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "Details": "C:\\Users\\alice\\AppData\\Roaming\\update.exe",
        "Image": "C:\\Windows\\System32\\reg.exe", "User": "CORP\\alice", "Computer": "WS-104",
    }),
    (480, "sysmon", "WS-104", "alice", {
        "EventID": 10, "SourceImage": "C:\\Users\\alice\\AppData\\Roaming\\update.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010",
        "User": "CORP\\alice", "Computer": "WS-104",
    }),
    (720, "okta", None, "admin", {
        "eventType": "user.session.start",
        "actor": {"alternateId": "admin@corp.local"},
        "client": {"ipAddress": "10.1.4.22", "geographicalContext": {"country": "US"}},
        "outcome": {"result": "SUCCESS"},
        "displayMessage": "User login to Okta (new device, no MFA prompt)",
    }),
    (900, "sysmon", "WS-104", "alice", {
        "EventID": 3, "Image": "C:\\Windows\\System32\\services.exe",
        "DestinationIp": "10.1.8.14", "DestinationPort": 445, "DestinationHostname": "SRV-02",
        "Protocol": "tcp", "User": "CORP\\alice", "Computer": "WS-104",
    }),
    (960, "sysmon", "SRV-02", "admin", {
        "EventID": 1, "Image": "C:\\Windows\\PSEXESVC.exe",
        "CommandLine": "PSEXESVC.exe -s cmd.exe",
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "User": "CORP\\admin", "Computer": "SRV-02",
    }),
    (1200, "sysmon", "SRV-02", "admin", {
        "EventID": 1, "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\Windows\\Temp\\stage.dll,EntryPoint",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\admin", "Computer": "SRV-02",
    }),
    (1500, "firewall", "SRV-02", None, {
        "action": "allow", "src_ip": "10.1.8.14", "dst_ip": "91.198.174.12",
        "dst_port": 443, "protocol": "tcp", "bytes_out": 536870912,
        "domain": "cdn-metrics-upload.ru", "duration_s": 340,
    }),
]

BENIGN_USERS = ["bob", "alice", "svc_backup"]
BENIGN_PROCS = ["chrome.exe", "slack.exe", "Code.exe", "explorer.exe", "outlook.exe"]


def noise_events(t: float) -> list[tuple[float, str, str | None, str | None, dict]]:
    out = []
    if random.random() < 0.5:
        u = random.choice(BENIGN_USERS)
        out.append((t, "okta", None, u, {
            "eventType": "user.session.start",
            "actor": {"alternateId": f"{u}@corp.local"},
            "client": {"ipAddress": f"73.15.{random.randint(1,254)}.{random.randint(1,254)}",
                       "geographicalContext": {"country": "US"}},
            "outcome": {"result": "SUCCESS"},
            "displayMessage": "User login to Okta",
        }))
    if random.random() < 0.6:
        u = random.choice(BENIGN_USERS)
        host = {"bob": "WS-219", "alice": "WS-104"}.get(u, "WS-219")
        proc = random.choice(BENIGN_PROCS)
        out.append((t, "sysmon", host, u, {
            "EventID": 1, "Image": f"C:\\Program Files\\{proc}",
            "CommandLine": proc, "ParentImage": "C:\\Windows\\explorer.exe",
            "User": f"CORP\\{u}", "Computer": host,
        }))
    if random.random() < 0.6:
        out.append((t, "firewall", "WS-219", None, {
            "action": "allow", "src_ip": "10.1.9.31",
            "dst_ip": f"151.101.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": 443, "protocol": "tcp",
            "bytes_out": random.randint(2_000, 300_000), "domain": "cdn.example.com",
        }))
    return out


def emit(source: str, host, user, raw):
    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source, "host": host, "user": user, "raw": raw,
    }
    path = os.path.join(LOG_DIR, f"{source}.log")
    with open(path, "a") as f:
        f.write(json.dumps(line) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--speed", type=float, default=60.0, help="timeline compression (60 = 30min campaign in 30s)")
    ap.add_argument("--burst", action="store_true", help="write everything immediately")
    ap.add_argument("--noise-interval", type=float, default=3.0, help="avg seconds between noise batches (real time)")
    args = ap.parse_args()
    os.makedirs(LOG_DIR, exist_ok=True)

    if args.burst:
        for _, source, host, user, raw in CAMPAIGN:
            emit(source, host, user, raw)
        for t in [i * 30 for i in range(60)]:
            for _, source, host, user, raw in noise_events(t):
                emit(source, host, user, raw)
        print(f"wrote {len(CAMPAIGN)} campaign + noise events to {LOG_DIR}")
        return

    print(f"streaming campaign into {LOG_DIR} (speed x{args.speed})")
    timeline = sorted(CAMPAIGN, key=lambda e: e[0])
    start = time.time()
    next_noise = 0.0
    for offset, source, host, user, raw in timeline:
        target = offset / args.speed
        while time.time() - start < target:
            if time.time() - start >= next_noise:
                for _, s, h, u, r in noise_events(time.time() - start):
                    emit(s, h, u, r)
                next_noise += args.noise_interval + random.uniform(-1, 1)
            time.sleep(0.2)
        emit(source, host, user, raw)
        print(f"  t+{offset:>5}s  {source:9} {host or '-':7} {user or '-'}")
    print("campaign complete")


if __name__ == "__main__":
    main()
