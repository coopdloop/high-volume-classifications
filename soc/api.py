"""Approval-queue API. Run: uvicorn soc.api:app --port 8000"""

import json
import os
import time
from contextlib import asynccontextmanager

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import store


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init()
    yield


app = FastAPI(title="jev-soc-agent", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/stats")
def stats():
    row = store.query(
        "SELECT COUNT(*) n, SUM(decision='escalate') esc, SUM(decision='review') rev,"
        " SUM(decision='benign') ben FROM events"
    )[0]
    cost = store.query("SELECT system, COUNT(*) n, SUM(cost) cost, AVG(latency_ms) ms FROM model_calls GROUP BY system")
    return {
        "classified": row["n"] or 0,
        "escalate": row["esc"] or 0,
        "review": row["rev"] or 0,
        "benign": row["ben"] or 0,
        "campaigns": store.query("SELECT COUNT(*) n FROM campaigns")[0]["n"],
        "approvals_pending": store.query("SELECT COUNT(*) n FROM approvals WHERE status='pending'")[0]["n"],
        "calls": {c["system"]: {"n": c["n"], "cost": c["cost"], "avg_ms": c["ms"]} for c in cost},
    }


@app.get("/scorecard")
def scorecard():
    try:
        with open(os.getenv("GROUND_TRUTH", "config/ground_truth.yml")) as f:
            gt = yaml.safe_load(f)
    except FileNotFoundError:
        return []
    out = []
    for s in gt.get("signals", []):
        pat = f"%{s['pattern']}%"
        present = store.query("SELECT COUNT(*) n FROM events WHERE raw LIKE ?", (pat,))[0]["n"]
        found = store.query("SELECT COUNT(*) n FROM events WHERE decision='escalate' AND raw LIKE ?", (pat,))[0]["n"]
        status = "found" if found else ("missed" if present else ("no-telemetry" if s.get("in_telemetry") is False else "absent"))
        out.append({**s, "present": present, "escalated": found, "status": status})
    return out


def _calibration_bins(pairs: list[tuple[float, int]], n_bins: int = 10) -> dict:
    """Reliability bins + Brier score for (predicted_prob, outcome) pairs."""
    n = len(pairs)
    brier = sum((p - y) ** 2 for p, y in pairs) / n
    base = sum(y for _, y in pairs) / n
    baseline = sum((base - y) ** 2 for _, y in pairs) / n  # always predicting base rate
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(n_bins)]
    for p, y in pairs:
        buckets[min(int(p * n_bins), n_bins - 1)].append((p, y))
    out = [
        {
            "range": f"{i / n_bins:.1f}-{(i + 1) / n_bins:.1f}",
            "n": len(b),
            "mean_predicted": round(sum(p for p, _ in b) / len(b), 4),
            "observed_frequency": round(sum(y for _, y in b) / len(b), 4),
        }
        for i, b in enumerate(buckets) if b
    ]
    return {
        "events": n,
        "positives": sum(y for _, y in pairs),
        "base_rate": round(base, 4),
        "brier": round(brier, 4),
        "brier_baseline": round(baseline, 4),
        "skill": round(1 - brier / baseline, 4) if baseline > 0 else None,
        "bins": out,
    }


@app.get("/calibration")
def calibration(bins: int = 10):
    """Is System 1's is_suspicious actually calibrated? Reliability bins + Brier
    score against ground-truth labels (attack = raw matches a signal pattern)."""
    try:
        with open(os.getenv("GROUND_TRUTH", "config/ground_truth.yml")) as f:
            gt = yaml.safe_load(f)
    except FileNotFoundError:
        raise HTTPException(404, "no ground truth file (set GROUND_TRUTH)")
    patterns = [s["pattern"] for s in gt.get("signals", []) if s.get("in_telemetry", True)]
    if not patterns:
        raise HTTPException(404, "no in-telemetry ground-truth signals")
    label = "CASE WHEN " + " OR ".join(["raw LIKE ?"] * len(patterns)) + " THEN 1 ELSE 0 END"
    rows = store.query(
        f"SELECT is_suspicious, {label} AS attack FROM events WHERE is_suspicious IS NOT NULL",
        tuple(f"%{p}%" for p in patterns),
    )
    if not rows:
        return {"events": 0, "bins": []}
    pairs = [(min(1.0, max(0.0, float(r["is_suspicious"]))), int(r["attack"])) for r in rows]
    result = _calibration_bins(pairs, max(2, min(bins, 50)))
    result["label"] = "attack=1 if raw matches any in-telemetry ground-truth signal pattern"
    return result


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


@app.get("/campaigns/{campaign_id}")
def campaign_detail(campaign_id: int):
    rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
    if not rows:
        raise HTTPException(404, "campaign not found")
    c = rows[0]
    for k in ("hosts", "users", "tactics", "event_ids"):
        c[k] = json.loads(c[k])
    ids = c["event_ids"][-50:]
    c["events"] = store.query(
        f"SELECT id, ts, source, host, user, is_suspicious, severity, tactic, decision FROM events"
        f" WHERE id IN ({','.join('?' * len(ids))}) ORDER BY id DESC", tuple(ids),
    ) if ids else []
    c["approvals"] = store.query("SELECT * FROM approvals WHERE campaign_id = ? ORDER BY id", (campaign_id,))
    return c


@app.get("/events")
def events(decision: str | None = None, q: str | None = None, limit: int = 50, offset: int = 0):
    where, params = [], []
    if decision:
        where.append("decision = ?")
        params.append(decision)
    if q:
        where.append("(raw LIKE ? OR host LIKE ? OR user LIKE ?)")
        params += [f"%{q}%"] * 3
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = store.query(f"SELECT COUNT(*) n FROM events {w}", tuple(params))[0]["n"]
    rows = store.query(
        f"SELECT id, ts, source, host, user, is_suspicious, severity, tactic, needs_context, decision"
        f" FROM events {w} ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, min(limit, 200), offset),
    )
    return {"total": total, "rows": rows}


@app.get("/events/{event_id}")
def event_detail(event_id: int):
    rows = store.query("SELECT * FROM events WHERE id = ?", (event_id,))
    if not rows:
        raise HTTPException(404, "event not found")
    ev = rows[0]
    ev["calls"] = [_flatten_call(r) for r in
                   store.query("SELECT * FROM model_calls WHERE event_id = ? ORDER BY id", (event_id,))]
    ev["campaigns"] = [
        {"id": c["id"], "anchor": c["anchor"], "status": c["status"], "tactics": json.loads(c["tactics"])}
        for c in store.query("SELECT id, anchor, status, tactics, event_ids FROM campaigns")
        if event_id in json.loads(c["event_ids"])
    ]
    return ev


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
def model_calls(system: str | None = None, limit: int = 100, offset: int = 0):
    if system:
        rows = store.query("SELECT * FROM model_calls WHERE system = ? ORDER BY id DESC LIMIT ? OFFSET ?", (system, limit, offset))
        total = store.query("SELECT COUNT(*) n FROM model_calls WHERE system = ?", (system,))[0]["n"]
    else:
        rows = store.query("SELECT * FROM model_calls ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        total = store.query("SELECT COUNT(*) n FROM model_calls")[0]["n"]
    return {"total": total, "rows": [_flatten_call(r) for r in rows]}


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
