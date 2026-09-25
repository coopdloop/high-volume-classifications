"""Approval-queue API. Run: uvicorn soc.api:app --port 8000"""

import json
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import store

app = FastAPI(title="jev-soc-agent")


@app.on_event("startup")
def startup():
    store.init()


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/alerts")
def alerts(decision: str = "escalate", limit: int = 100):
    return store.query(
        "SELECT * FROM events WHERE decision = ? ORDER BY id DESC LIMIT ?",
        (decision, limit),
    )


@app.get("/campaigns")
def campaigns():
    rows = store.query("SELECT * FROM campaigns ORDER BY id DESC")
    for r in rows:
        for k in ("hosts", "users", "tactics", "event_ids"):
            r[k] = json.loads(r[k])
    return rows


@app.get("/approvals")
def approvals(status: str = "pending"):
    return store.query(
        "SELECT * FROM approvals WHERE status = ? ORDER BY id", (status,)
    )


def _flatten_call(r: dict) -> dict:
    """Flatten a model_calls row; surface JEV probability maps for System 1."""
    out = {k: r[k] for k in ("id", "ts", "system", "backend", "model", "event_id",
                             "campaign_id", "latency_ms", "cost")}
    out["ts_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"]))
    try:
        resp = json.loads(r["response"]) if r.get("response") else {}
    except (json.JSONDecodeError, TypeError):
        resp = {}
    if r["system"] == "system1":
        # JEV shape: {qname: {noul|choice|score, probabilities, confidence}}
        # emulated shape: {nouls: {...}, choices: {...}, scores: {...}}
        nouls = resp.get("nouls") or {k: v.get("noul") for k, v in resp.items() if isinstance(v, dict) and "noul" in v}
        choices = resp.get("choices") or {k: v for k, v in resp.items() if isinstance(v, dict) and "choice" in v}
        scores = resp.get("scores") or {k: v for k, v in resp.items() if isinstance(v, dict) and "score" in v}
        out["is_suspicious"] = nouls.get("is_suspicious")
        out["needs_context"] = nouls.get("needs_context")
        out["tactic"] = (choices.get("mitre_tactic") or {}).get("choice")
        out["tactic_probabilities"] = json.dumps((choices.get("mitre_tactic") or {}).get("probabilities", {}))
        out["severity"] = (scores.get("severity") or {}).get("score")
        out["severity_probabilities"] = json.dumps((scores.get("severity") or {}).get("probabilities", {}))
    elif r["system"] == "guardrail":
        gate = resp.get("gate") or {}
        out["disruptive_prob"] = gate.get("noul") if isinstance(gate, dict) else gate
    return out


@app.get("/model-calls")
def model_calls(system: str | None = None, limit: int = 100):
    if system:
        rows = store.query("SELECT * FROM model_calls WHERE system = ? ORDER BY id DESC LIMIT ?", (system, limit))
    else:
        rows = store.query("SELECT * FROM model_calls ORDER BY id DESC LIMIT ?", (limit,))
    return [_flatten_call(r) for r in rows]


@app.get("/model-calls/{call_id}")
def model_call_detail(call_id: int):
    rows = store.query("SELECT * FROM model_calls WHERE id = ?", (call_id,))
    if not rows:
        raise HTTPException(404, "call not found")
    r = rows[0]
    r["request"] = json.loads(r["request"])
    r["response"] = json.loads(r["response"])
    return r


class Decision(BaseModel):
    decision: str  # approve | reject


@app.post("/approvals/{approval_id}")
def decide_approval(approval_id: int, body: Decision):
    rows = store.query("SELECT * FROM approvals WHERE id = ?", (approval_id,))
    if not rows:
        raise HTTPException(404, "approval not found")
    if rows[0]["status"] != "pending":
        raise HTTPException(409, f"already {rows[0]['status']}")
    if body.decision == "approve":
        # SIMULATED execution point — hook real SOAR integrations here later
        status = "simulated-executed"
    elif body.decision == "reject":
        status = "rejected"
    else:
        raise HTTPException(400, "decision must be approve|reject")
    store.execute(
        "UPDATE approvals SET status = ?, decided_at = ? WHERE id = ?",
        (status, time.time(), approval_id),
    )
    return {"id": approval_id, "status": status}
