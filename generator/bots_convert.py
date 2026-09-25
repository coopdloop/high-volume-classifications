"""Convert Splunk Boss of the SOC (v3) dataset exports into this project's JSONL
format so they replay through the same Alloy -> Loki -> JEV pipeline.

Input: BOTS v3 JSON files (array of events with "sourcetype" and "_time") or
JSONL (one event per line). Download the dataset separately (several GB):
https://github.com/splunk/botsv3

Sourcetype mapping (best effort, override with --map src=dst):
  *sysmon*                      -> sysmon.log
  stream:ip / *firewall*        -> firewall.log
  ms:o365* / ms:aad* / okta*    -> okta.log
  everything else               -> skipped (counted in summary)

BOTS timestamps are historical (2018); Loki rejects very old samples by
default, so --retime (default on) shifts the dataset so its newest event is
"now" while preserving relative spacing.

Run: python generator/bots_convert.py --input botsv3.json --limit 50000
"""

import argparse
import glob
import json
import os
import time
from datetime import datetime, timezone

LOG_DIR = os.getenv("LOG_DIR", "data/logs")

DEFAULT_MAP = [
    ("sysmon", "sysmon"),
    ("stream:ip", "firewall"),
    ("firewall", "firewall"),
    ("ms:o365", "okta"),
    ("ms:aad", "okta"),
    ("okta", "okta"),
]


def parse_time(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def map_source(sourcetype: str, overrides: dict) -> str | None:
    st = (sourcetype or "").lower()
    if st in overrides:
        return overrides[st]
    for pat, dst in DEFAULT_MAP:
        if pat in st:
            return dst
    return None


def iter_events(path: str):
    with open(path) as f:
        head = f.read(1)
        f.seek(0)
        if head == "[":
            yield from json.load(f)
        else:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="BOTS json/jsonl file, dir, or glob")
    ap.add_argument("--outdir", default=LOG_DIR)
    ap.add_argument("--limit", type=int, default=0, help="max events to convert (0 = all)")
    ap.add_argument("--retime", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--map", action="append", default=[], help="sourcetype=dest overrides")
    args = ap.parse_args()

    overrides = dict(m.split("=", 1) for m in args.map)
    paths = sorted(
        p for pat in [args.input] for p in (
            glob.glob(pat) if any(c in pat for c in "*?[") else
            glob.glob(os.path.join(pat, "**", "*.json*"), recursive=True) if os.path.isdir(pat) else [pat]
        )
    )
    if not paths:
        raise SystemExit(f"no input files matched: {args.input}")

    os.makedirs(args.outdir, exist_ok=True)
    counts: dict[str, int] = {}
    skipped: dict[str, int] = {}
    events = []
    for path in paths:
        for ev in iter_events(path):
            dst = map_source(ev.get("sourcetype", ""), overrides)
            if not dst:
                skipped[ev.get("sourcetype", "?")] = skipped.get(ev.get("sourcetype", "?"), 0) + 1
                continue
            ts = parse_time(ev.get("_time", time.time()))
            host = ev.get("Computer") or ev.get("ComputerName") or ev.get("host") or ev.get("dvc")
            user = ev.get("User") or ev.get("user") or ev.get("Account_Name")
            if isinstance(user, str) and "\\" in user:
                user = user.split("\\")[-1]
            events.append((ts, dst, host, user, ev))
            counts[dst] = counts.get(dst, 0) + 1
            if args.limit and len(events) >= args.limit:
                break
        if args.limit and len(events) >= args.limit:
            break

    if not events:
        raise SystemExit("no convertible events found")

    events.sort(key=lambda e: e[0])
    offset = time.time() - events[-1][0] if args.retime else 0
    handles = {}
    try:
        for ts, dst, host, user, raw in events:
            line = {
                "ts": datetime.fromtimestamp(ts + offset, tz=timezone.utc).isoformat(),
                "source": dst, "host": host, "user": user, "raw": raw,
            }
            fh = handles.setdefault(dst, open(os.path.join(args.outdir, f"{dst}.log"), "a"))
            fh.write(json.dumps(line) + "\n")
    finally:
        for fh in handles.values():
            fh.close()

    print(f"converted {len(events)} events -> {args.outdir}: {counts}")
    if skipped:
        top = sorted(skipped.items(), key=lambda kv: -kv[1])[:10]
        print(f"skipped sourcetypes (top 10): {top}")


if __name__ == "__main__":
    main()
