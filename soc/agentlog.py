"""Model-call observability: every System-1 / System-2 / guardrail call is
recorded to SQLite (queryable via the API) and appended as JSONL to
$LOG_DIR/agent.log, which Alloy ships to Loki as job="soc-agent" so JEV's
probability maps are visible chronologically next to the raw logs.
"""

import json
import os
import time
from datetime import datetime, timezone

from . import store

LOG_DIR = os.getenv("LOG_DIR", "data/logs")


def _line(rec: dict) -> dict:
    """Compact form for the Loki stream (state/prompt truncated)."""
    req = rec.get("request") or {}
    return {
        "ts": datetime.fromtimestamp(rec["ts"], tz=timezone.utc).isoformat(),
        "source": "agent",
        "system": rec["system"],
        "backend": rec.get("backend"),
        "model": rec.get("model"),
        "latency_ms": round(rec.get("latency_ms") or 0, 1),
        "cost": rec.get("cost"),
        "event_id": rec.get("event_id"),
        "campaign_id": rec.get("campaign_id"),
        "state_preview": str(req.get("state") or req.get("prompt") or "")[:800],
        "answers": rec.get("response"),
    }


def log_model_call(system: str, backend: str, model: str, latency_ms: float,
                   cost: float | None, request: dict, response,
                   event_id: int | None = None, campaign_id: int | None = None) -> int:
    rec = {
        "ts": time.time(), "system": system, "backend": backend, "model": model,
        "latency_ms": latency_ms, "cost": cost,
        "event_id": event_id, "campaign_id": campaign_id,
        "request": request, "response": response,
    }
    row_id = store.insert_model_call(rec)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "agent.log"), "a") as f:
            f.write(json.dumps(_line(rec)) + "\n")
    except OSError as e:
        print(f"[agentlog] loki mirror write failed: {e}")
    return row_id
