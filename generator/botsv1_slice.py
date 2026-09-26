"""Slice the BOTS v1 dataset (json-by-sourcetype exports) into a bounded,
replayable log set for the JEV SOC pipeline.

Two attack windows are kept at full fidelity inside content-blind logging
policy (the kind any SOC applies at ingest: drop image-load noise, app chatter
ports, app-ctrl logs; sample web filter / http). The agents get no hints about
*which* events are malicious.

Windows (MDT):
  A  2016-08-10 15:30-16:30   P01s0n1vy APT: scan, Joomla brute force, defacement
  B  2016-08-24 10:30-11:30   Cerber ransomware: USB -> macro -> VBS -> encrypt

Retime: window A replays at [now-125m, now-65m], window B at [now-60m, now].

Run: python generator/botsv1_slice.py
Ground truth: docs/botsv1-ground-truth.md
"""

import gzip
import json
import os
import random
import time
from datetime import datetime, timedelta, timezone

DATASETS = {
    "datasets/botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz": "sysmon",
    "datasets/botsv1.fgt_utm.json.gz": "firewall",
    "datasets/botsv1.stream-http.json.gz": "firewall",
}
LOG_DIR = os.getenv("LOG_DIR", "data/logs")

# MDT = UTC-6; dataset timestamps look like "2016-08-24 10:48:21.000 MDT"
MDT = timezone(timedelta(hours=-6))

def ts(s: str) -> datetime:
    return datetime.strptime(s.rsplit(" ", 1)[0], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=MDT)

WINDOW_A = (ts("2016-08-10 15:30:00.0 MDT"), ts("2016-08-10 16:30:00.0 MDT"))
WINDOW_B = (ts("2016-08-24 10:30:00.0 MDT"), ts("2016-08-24 11:30:00.0 MDT"))

# Content-blind logging policy (no IOC keywords anywhere)
SYSMON_DROP_CODES = {"7"}                       # image load: classic ingest-time exclusion
SYSMON_NET_KEEP_PORTS = {"53", "80", "443", "445", "3389", "22", "25", "587", "110", "143", "993", "995", "8080"}
FGT_DROP_SUBTYPES = {"app-ctrl"}                # application control chatter
FGT_WEBFILTER_SAMPLE = 0.05
FGT_IPS_SAMPLE = 0.25                             # fortigate IPS is FP-heavy noise
HTTP_SAMPLE = {"A": 0.05, "B": 1.0}             # brute force alone is ~22k events in A

random.seed(42)


def keep_sysmon(r: dict) -> bool:
    code = r.get("EventCode", "")
    if code in SYSMON_DROP_CODES:
        return False
    if code == "3":
        return r.get("DestinationPort", "") in SYSMON_NET_KEEP_PORTS
    return True


def keep_fgt(r: dict) -> bool:
    sub = r.get("subtype", "")
    if sub in FGT_DROP_SUBTYPES:
        return False
    if sub == "webfilter":
        return random.random() < FGT_WEBFILTER_SAMPLE
    if sub == "ips":
        return random.random() < FGT_IPS_SAMPLE
    return True


def window_of(t: datetime) -> str | None:
    if WINDOW_A[0] <= t <= WINDOW_A[1]:
        return "A"
    if WINDOW_B[0] <= t <= WINDOW_B[1]:
        return "B"
    return None


def main():
    now = time.time()
    # window A ends 65 min ago; window B ends now
    shift = {
        "A": now - 65 * 60 - WINDOW_A[1].timestamp(),
        "B": now - WINDOW_B[1].timestamp(),
    }
    os.makedirs(LOG_DIR, exist_ok=True)
    out = {lane: open(os.path.join(LOG_DIR, f"{lane}.log"), "a") for lane in ("sysmon", "firewall")}
    counts = {"A": 0, "B": 0}
    try:
        events = []
        for path, lane in DATASETS.items():
            is_http = "stream-http" in path
            with gzip.open(path, "rt") as f:
                for line in f:
                    try:
                        r = json.loads(line)["result"]
                    except (json.JSONDecodeError, KeyError):
                        continue
                    t_raw = r.get("_time")
                    if not t_raw:
                        continue
                    try:
                        w = window_of(ts(t_raw))
                    except ValueError:
                        continue
                    if not w:
                        continue
                    if lane == "sysmon" and not keep_sysmon(r):
                        continue
                    if "fgt_utm" in path and not keep_fgt(r):
                        continue
                    if is_http and random.random() > HTTP_SAMPLE[w]:
                        continue
                    events.append((ts(t_raw).timestamp() + shift[w], lane, r))
                    counts[w] += 1
        events.sort(key=lambda e: e[0])
        for t, lane, r in events:
            host = r.get("Computer") or r.get("ComputerName") or r.get("src") or r.get("host")
            user = r.get("User") or r.get("user")
            out[lane].write(json.dumps({
                "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                "source": lane, "host": host, "user": user, "raw": r,
            }) + "\n")
    finally:
        for fh in out.values():
            fh.close()
    print(f"wrote {counts['A'] + counts['B']} events (A={counts['A']}, B={counts['B']}) -> {LOG_DIR}")


if __name__ == "__main__":
    main()
