"""System-2: correlates escalated events into campaigns, generates playbooks,
and gates each SOAR action through JEV (Auto Mode guardrail) before queuing
it for human approval.

Run: python -m soc.correlate
"""

import json
import os
import re
import time

import httpx
import yaml
from dotenv import load_dotenv

from . import agentlog, store
from .jev_client import get_classifier, noul_gate

load_dotenv()
INTERVAL = float(os.getenv("CORRELATE_INTERVAL", "15"))
REVIEW_INTERVAL = float(os.getenv("REVIEW_INTERVAL", "300"))
CURSOR_FILE = "data/correlate_cursor"

SYSTEM2_PROMPT = """You are a SOC incident-response reasoning engine (System 2).
Below are escalated security events (each already classified by a fast System-1
model with MITRE tactic, suspicion probability, and severity) that appear to be
part of one campaign clustered around {anchor}.

EVENTS:
{events}

Return ONLY JSON:
{{
  "narrative": "concise campaign summary: who, what, attack chain so far, likely objective",
  "confidence": 0-1,
  "recommended_actions": [
    {{"action": "specific containment/eradication step", "risk": "low|medium|high",
      "reason": "why this action"}}
  ]
}}
Prefer reversible, least-disruptive actions first. 3-6 actions max."""

REVIEW_PROMPT = """You are a SOC analyst doing a periodic second pass over events that a
fast triage model routed to a human REVIEW queue (neither clearly malicious nor
clearly benign). Decide which, if any, warrant escalation to incident response
when considered together.

REVIEW-QUEUE EVENTS (id, source, host, user, tactic, suspicion, severity, raw):
{events}

Return ONLY JSON: {{"escalate_ids": [<id>, ...], "rationale": "one sentence"}}
Escalate only when events form a meaningful pattern or one is clearly dangerous.
Empty list is a fine answer."""


GUARDRAIL_QUESTION = (
    "Executing this containment action could disrupt legitimate business "
    "operations or cause data loss if the detection were a false positive."
)


def load_policy():
    with open(os.getenv("THRESHOLDS", "config/thresholds.yml")) as f:
        return yaml.safe_load(f)


def get_cursor() -> int:
    try:
        return int(open(CURSOR_FILE).read().strip())
    except Exception:
        return 0


def save_cursor(i: int):
    os.makedirs("data", exist_ok=True)
    with open(CURSOR_FILE, "w") as f:
        f.write(str(i))


def cluster(events: list[dict], policy: dict) -> dict[str, list[dict]]:
    """Group escalations by anchor (host or user); return anchors that trip campaign rules."""
    groups: dict[str, list[dict]] = {}
    for e in events:
        for key in (e.get("host"), e.get("user")):
            if key:
                groups.setdefault(key, []).append(e)
    min_t = policy["campaign"]["min_tactics"]
    min_e = policy["campaign"]["min_events"]
    out = {}
    for anchor, evs in groups.items():
        tactics = {e["tactic"] for e in evs if e.get("tactic") and e["tactic"] != "benign"}
        # merge with events already attached to an open campaign on this anchor
        existing = store.find_open_campaign(anchor)
        if existing:
            tactics |= set(json.loads(existing["tactics"]))
            total = len(evs) + len(json.loads(existing["event_ids"]))
        else:
            total = len(evs)
        if len(tactics) >= min_t or total >= min_e:
            out[anchor] = evs
    return out


def system2_reason(events: list[dict], anchor: str) -> dict:
    ev_lines = "\n".join(
        f"- [{e['source']}] host={e['host']} user={e['user']} tactic={e['tactic']} "
        f"susp={e['is_suspicious']:.2f} sev={e['severity']:.1f} raw={e['raw'][:400]}"
        for e in events
    )
    return llm_json(SYSTEM2_PROMPT.format(anchor=anchor, events=ev_lines))


def process_campaign(anchor: str, events: list[dict], classifier):
    existing = store.find_open_campaign(anchor)
    if existing:
        campaign = existing
        campaign["hosts"] = sorted(set(json.loads(existing["hosts"])) | {e["host"] for e in events if e.get("host")})
        campaign["users"] = sorted(set(json.loads(existing["users"])) | {e["user"] for e in events if e.get("user")})
        campaign["tactics"] = sorted(set(json.loads(existing["tactics"])) | {e["tactic"] for e in events if e.get("tactic")})
        campaign["event_ids"] = json.loads(existing["event_ids"]) + [e["id"] for e in events]
    else:
        campaign = {
            "anchor": anchor,
            "hosts": sorted({e["host"] for e in events if e.get("host")}),
            "users": sorted({e["user"] for e in events if e.get("user")}),
            "tactics": sorted({e["tactic"] for e in events if e.get("tactic")}),
            "event_ids": [e["id"] for e in events],
        }
    print(f"\n[campaign] {'updating' if existing else 'NEW'} campaign on anchor={anchor} "
          f"tactics={campaign['tactics']}")
    analysis = system2_reason(events, anchor)
    campaign["narrative"] = analysis.get("narrative", "")
    cid = store.upsert_campaign(campaign)
    print(f"[campaign #{cid}] {campaign['narrative']}")

    for action in analysis.get("recommended_actions", []):
        # Auto Mode guardrail: JEV gates the SOAR action before it enters the queue
        gate_rec: dict = {}
        p = noul_gate(classifier, json.dumps(action), GUARDRAIL_QUESTION, record=gate_rec)
        agentlog.log_model_call(
            system="guardrail", backend=gate_rec.get("backend", "?"),
            model=gate_rec.get("model", "?"), latency_ms=gate_rec.get("latency_ms", 0),
            cost=gate_rec.get("cost"),
            request={"state": json.dumps(action), "question": GUARDRAIL_QUESTION},
            response=gate_rec.get("raw"), campaign_id=cid,
        )
        action["disruptive_prob"] = p
        if p > 0.7 and action.get("risk") != "high":
            action["risk"] = "high"
        aid = store.insert_approval(cid, action)
        print(f"  [approval #{aid}] ({action['risk']}, disrupt_p={p:.2f}) {action['action']}")


def llm_json(prompt: str, purpose: str = "system2", campaign_id: int | None = None) -> dict:
    model = os.getenv("SYSTEM2_MODEL", "openai/gpt-4o-mini")
    t0 = time.time()
    r = httpx.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        },
        timeout=120,
    )
    r.raise_for_status()
    data = r.json()
    text = data["choices"][0]["message"]["content"]
    parsed = json.loads(re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M))
    agentlog.log_model_call(
        system=purpose, backend="openrouter-chat", model=model,
        latency_ms=(time.time() - t0) * 1000,
        cost=(data.get("usage") or {}).get("cost"),
        request={"prompt": prompt}, response=parsed, campaign_id=campaign_id,
    )
    return parsed


def review_batch(policy: dict, classifier):
    """Periodic System-2 second pass over the review queue."""
    window_sec = int(policy.get("window_minutes", 20)) * 60
    rows = store.query(
        "SELECT * FROM events WHERE decision='review' AND ts > ? ORDER BY id LIMIT 50",
        (time.time() - window_sec,),
    )
    if not rows:
        return
    ev_lines = "\n".join(
        f"- id={e['id']} [{e['source']}] host={e['host']} user={e['user']} tactic={e['tactic']} "
        f"susp={e['is_suspicious']:.2f} sev={e['severity']:.1f} raw={e['raw'][:300]}"
        for e in rows
    )
    try:
        verdict = llm_json(REVIEW_PROMPT.format(events=ev_lines))
    except Exception as e:
        print(f"[review] llm error: {e}")
        return
    ids = [i for i in verdict.get("escalate_ids", []) if isinstance(i, int)]
    if not ids:
        print(f"[review] {len(rows)} reviewed, none escalated")
        return
    print(f"[review] escalating {ids}: {verdict.get('rationale', '')}")
    placeholders = ",".join("?" * len(ids))
    store.execute(f"UPDATE events SET decision='escalate' WHERE id IN ({placeholders})", tuple(ids))
    escalated = store.query(f"SELECT * FROM events WHERE id IN ({placeholders})", tuple(ids))
    for anchor, evs in cluster(escalated, policy).items():
        try:
            process_campaign(anchor, evs, classifier)
        except Exception as e:
            print(f"[review] campaign error on {anchor}: {e}")


def stitch_campaigns():
    """Merge open campaigns whose host/user sets overlap (cross-anchor stitching)."""
    open_campaigns = store.query("SELECT * FROM campaigns WHERE status='open' ORDER BY id")
    if len(open_campaigns) < 2:
        return
    merged_into: dict[int, int] = {}
    for i, a in enumerate(open_campaigns):
        if a["id"] in merged_into:
            continue
        a_hosts, a_users = set(json.loads(a["hosts"])), set(json.loads(a["users"]))
        for b in open_campaigns[i + 1:]:
            if b["id"] in merged_into:
                continue
            b_hosts, b_users = set(json.loads(b["hosts"])), set(json.loads(b["users"]))
            if (a_hosts & b_hosts) or (a_users & b_users):
                store.execute(
                    "UPDATE campaigns SET hosts=?, users=?, tactics=?, event_ids=?, updated_at=? WHERE id=?",
                    (
                        json.dumps(sorted(a_hosts | b_hosts)),
                        json.dumps(sorted(a_users | b_users)),
                        json.dumps(sorted(set(json.loads(a["tactics"])) | set(json.loads(b["tactics"])))),
                        json.dumps(json.loads(a["event_ids"]) + json.loads(b["event_ids"])),
                        time.time(), a["id"],
                    ),
                )
                store.execute("UPDATE campaigns SET status='merged' WHERE id=?", (b["id"],))
                merged_into[b["id"]] = a["id"]
                print(f"[stitch] campaign #{b['id']} (anchor={b['anchor']}) merged into #{a['id']} (anchor={a['anchor']})")
                a_hosts |= b_hosts
                a_users |= b_users


def main():
    store.init()
    policy = load_policy()
    window_sec = int(policy.get("window_minutes", 20)) * 60
    classifier = get_classifier()
    cursor = get_cursor()
    print(f"[correlate] window={window_sec}s interval={INTERVAL}s review_interval={REVIEW_INTERVAL}s")
    last_review = time.time()
    while True:
        events = store.escalations_since(cursor, window_sec)
        if events:
            cursor = max(e["id"] for e in events)
            for anchor, evs in cluster(events, policy).items():
                try:
                    process_campaign(anchor, evs, classifier)
                except Exception as e:
                    print(f"[correlate] error on {anchor}: {e}")
            save_cursor(cursor)
            stitch_campaigns()
        if time.time() - last_review >= REVIEW_INTERVAL:
            last_review = time.time()
            review_batch(policy, classifier)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
