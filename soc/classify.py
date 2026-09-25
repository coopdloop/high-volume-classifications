"""System-1 consumer: polls Loki, enriches, classifies with JEV, routes by policy.

Run: python -m soc.classify
"""

import json
import os
import time
from datetime import datetime, timezone

import httpx
import yaml
from dotenv import load_dotenv

from . import enrich, store
from .jev_client import get_classifier

load_dotenv()
LOKI = os.getenv("LOKI_URL", "http://localhost:3100")
POLL = float(os.getenv("POLL_INTERVAL", "5"))
CURSOR_FILE = "data/loki_cursor"


def load_policy():
    with open(os.getenv("THRESHOLDS", "config/thresholds.yml")) as f:
        return yaml.safe_load(f)


def decide(c, host_criticality, policy) -> str:
    ctx = {
        "is_suspicious": c.nouls.get("is_suspicious", 0.0),
        "needs_context": c.nouls.get("needs_context", 0.0),
        "severity": c.scores.get("severity", {}).get("score", 1.0),
        "suspicious_confidence": 1.0,  # noul questions: probability doubles as confidence
        "severity_confidence": c.scores.get("severity", {}).get("confidence", 1.0),
        "tactic_confidence": c.choices.get("mitre_tactic", {}).get("confidence", 1.0),
        "tactic": c.choices.get("mitre_tactic", {}).get("choice", "benign"),
        "host_criticality": host_criticality or 1,
    }
    # suspicious_confidence: distance from 0.5 (a calibrated noul is most
    # uncertain near 0.5), unless the backend reports an explicit confidence.
    ctx["suspicious_confidence"] = min(1.0, abs(ctx["is_suspicious"] - 0.5) * 2)
    for expr in policy.get("escalate", []):
        if eval(expr, {"__builtins__": {}}, ctx):
            return "escalate"
    for expr in policy.get("benign", []):
        if eval(expr, {"__builtins__": {}}, ctx):
            return "benign"
    return policy.get("default", "review")


def get_cursor() -> int:
    try:
        return int(open(CURSOR_FILE).read().strip())
    except Exception:
        # start 10 min back, in nanoseconds
        return int((time.time() - 600) * 1e9)


def save_cursor(ns: int):
    os.makedirs("data", exist_ok=True)
    with open(CURSOR_FILE, "w") as f:
        f.write(str(ns))


def fetch_logs(since_ns: int) -> list[tuple[int, dict]]:
    r = httpx.get(
        f"{LOKI}/loki/api/v1/query_range",
        params={
            "query": '{job="soc"}',
            "start": since_ns,
            "direction": "forward",
            "limit": 500,
        },
        timeout=30,
    )
    r.raise_for_status()
    out = []
    for stream in r.json().get("data", {}).get("result", []):
        for ts_ns, line in stream.get("values", []):
            try:
                out.append((int(ts_ns), json.loads(line)))
            except json.JSONDecodeError:
                continue
    out.sort(key=lambda x: x[0])
    return out


def main():
    store.init()
    policy = load_policy()
    window_sec = int(policy.get("window_minutes", 20)) * 60
    assets = enrich.load_assets()
    classifier = get_classifier()
    cursor = get_cursor()
    print(f"[classify] backend={classifier.name} polling {LOKI} every {POLL}s")
    while True:
        try:
            events = fetch_logs(cursor)
        except Exception as e:
            print(f"[classify] loki error: {e}")
            time.sleep(POLL)
            continue
        for ts_ns, ev in events:
            cursor = max(cursor, ts_ns + 1)
            ev["ts"] = ts_ns / 1e9
            ev["ts_iso"] = datetime.fromtimestamp(ev["ts"], tz=timezone.utc).isoformat()
            state = enrich.build_state(ev, window_sec, assets)
            try:
                c = classifier.classify(state)
            except Exception as e:
                print(f"[classify] classifier error: {e}")
                continue
            host_info = (assets.get("hosts") or {}).get(ev.get("host"), {})
            decision = decide(c, host_info.get("criticality"), policy)
            rec = {
                **ev,
                "is_suspicious": c.nouls.get("is_suspicious"),
                "suspicious_confidence": min(1.0, abs(c.nouls.get("is_suspicious", 0.5) - 0.5) * 2),
                "severity": c.scores.get("severity", {}).get("score"),
                "severity_confidence": c.scores.get("severity", {}).get("confidence"),
                "tactic": c.choices.get("mitre_tactic", {}).get("choice"),
                "tactic_confidence": c.choices.get("mitre_tactic", {}).get("confidence"),
                "needs_context": c.nouls.get("needs_context"),
                "decision": decision,
                "backend": c.backend,
            }
            store.insert_event(rec)
            flag = {"escalate": "!!", "review": "??", "benign": "  "}[decision]
            print(f"{flag} [{ev['source']:8}] {(ev.get('host') or '-'):7} {(ev.get('user') or '-'):10} "
                  f"susp={rec['is_suspicious']:.2f} sev={rec['severity']:.1f} "
                  f"tactic={rec['tactic'] or '-':18} -> {decision}")
            save_cursor(cursor)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
