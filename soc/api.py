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
