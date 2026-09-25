# jev-soc-agent

SOC observability POC: **System 1 / System 2** architecture for automated log triage and SOAR.

- **System 1** = [JEV](https://typesafe.ai/blog/introducing-system-one-models-and-jev) (TypeSafe AI) —
  a non-generative "System One" model. It takes a `state` (enriched log event) and answers
  typed questions in parallel with calibrated probabilities: **Noul** (yes/no), **Choice**
  (pick from options), **Score** (ordered levels). ~200x faster / ~400x cheaper than LLM
  classification, so it can sit on the hot path of every log line.
- **System 2** = an LLM doing slow, deep reasoning over the events System 1 escalates:
  campaign correlation, narrative generation, and SOAR playbook decisions (simulated,
  behind a human approval queue). Each playbook action is gated through JEV first
  (the [Auto Mode](https://www.langchain.com/blog/building-a-harness-with-jev) guardrail pattern).

## Architecture

```
generator/campaign.py ──JSONL──▶ Alloy ──▶ Loki ──▶ soc/classify.py (System 1: JEV)
   (synthetic APT: phishing →       │                    │ enrich (assets.yml +
    exec → persist → privesc →      ▼                    │  recent-escalation counts)
    lateral → exfil + noise)   Grafana :3000             ▼
                                              policy thresholds (thresholds.yml)
                                              escalate / review / benign
                                                       │ escalate
                                                       ▼
                                          soc/correlate.py (System 2)
                                          campaign clustering (≥3 tactics or
                                          ≥5 events per host/user in 20m window)
                                          → LLM narrative + playbook
                                          → JEV guardrail per action
                                                       ▼
                                          soc/api.py :8000 approval queue
                                          (approve → simulated-executed)
```

## Quickstart

```bash
# 1. log platform
docker compose up -d                 # Loki :3100, Alloy :12345, Grafana :3000

# 2. python env
uv venv && source .venv/bin/activate
pip install -r requirements.txt
cp env.example .env                  # add OPENROUTER_API_KEY (and/or TYPESAFE_API_KEY)

# 3. terminals
python -m soc.classify               # System 1 consumer (polls Loki)
python -m soc.correlate              # System 2 campaign engine
uvicorn soc.api:app --port 8000      # approval queue (docs at /docs)

# 4. run the attack
python generator/campaign.py --speed 60     # 30-min campaign in ~30s + benign noise
# or: python generator/campaign.py --burst  # everything at once
```

Watch:

- `soc.classify` stdout: per-event JEV probabilities + routing decision
- `soc.correlate` stdout: campaign detection, narrative, gated playbook actions
- Grafana → Explore → Loki → `{job="soc"}` (filter `{source="sysmon"}` etc.)
- API: `curl localhost:8000/approvals?status=pending`,
  `curl -X POST localhost:8000/approvals/1 -H 'content-type: application/json' -d '{"decision":"approve"}'`

## System-1 question set (per event, one parallel request)

| question | type | purpose |
|---|---|---|
| `is_suspicious` | Noul | p(malicious) → primary routing signal |
| `mitre_tactic` | Choice | 10-way ATT&CK tactic classification |
| `severity` | Score | 1–5 ordinal severity with confidence |
| `needs_context` | Noul | flags events only meaningful in a sequence |

## Routing policy (`config/thresholds.yml`)

- **Escalate**: `suspicious ≥ 0.9`, or `severity ≥ 3 & suspicious ≥ 0.7`, or
  **low confidence** (`|p - 0.5| * 2 < 0.55` → safe default), or
  `needs_context ≥ 0.8 & severity ≥ 2.5 & suspicious ≥ 0.5`
- **Benign**: `severity ≤ 2 & suspicious < 0.3 & confidence ≥ 0.8`
- **Default**: `review` queue

Tradeoff knob: the low-confidence rule trades System-2 cost for recall on novel
attacks; tighten it for volume, loosen it for safety.

## Backends

JEV is on **OpenRouter** (`typesafe/jev-1.13`) via the Decisions API
(`POST /api/alpha/decisions`) — one OpenRouter key runs the whole stack, no
TypeSafe account or waitlist. `SYSTEM1_BACKEND` selects: `auto` (default:
TypeSafe direct if `TYPESAFE_API_KEY` set, else JEV-via-OpenRouter),
`typesafe`, `jev-openrouter`, or `emulated` (a chat LLM approximating the
Noul/Choice/Score interface — useful as a comparison baseline, but its
probabilities are not RLCD-calibrated). System 2 uses `SYSTEM2_MODEL` via
OpenRouter chat completions.

JEV scores are 0-based indices over the criteria; the client normalizes to
1..N so `thresholds.yml` reads naturally (severity 1–5).

## Demo scenario

APT-DEMO: Okta login for `alice` from a TOR exit (RU) → Word macro spawns
encoded PowerShell on WS-104 → registry Run-key persistence → LSASS access →
SMB to SRV-02 → PSEXESVC as `admin` → rundll32 staging → 512 MB egress to a
rare `.ru` domain. System 1 escalates the chain; System 2 clusters ≥3 distinct
tactics on an anchor (host/user) into a campaign and proposes containment.

## System 2 extras

- **Review-queue second pass** (`REVIEW_INTERVAL`, default 300s): the LLM
  re-examines events JEV routed to `review` in the current window, in batch,
  and can escalate them into campaign clustering.
- **Cross-anchor stitching**: open campaigns whose host/user sets overlap are
  merged automatically (e.g. a campaign anchored on `alice` and one on
  `WS-104` become one).

## Agent observability (model-call logging)

Every model call is recorded with full request/response, model id, latency,
and `usage.cost` — including JEV's **complete probability maps** (per-option
choice probabilities, per-level score distributions, noul values):

- SQLite `model_calls` table → `GET /model-calls?system=system1|system2|guardrail`
  (flattened) and `GET /model-calls/{id}` (full raw state + answers)
- Mirrored as JSONL to `data/logs/agent.log` → Alloy ships it to Loki as
  `job="soc-agent"`, so in Explore you can watch JEV's decisions
  chronologically next to the raw logs: `{job="soc-agent"} | json`
- Grafana panel **"System 1 — JEV decision log (probability maps)"** shows
  p(suspicious), p(needs_context), severity, tactic, the full tactic
  probability map, latency, and cost per call

## Grafana dashboard

`docker compose up -d` provisions a **JEV SOC Agent** dashboard (SOC folder):
Loki log volume + raw logs, plus System-1 escalations, System-2 campaigns, and
the pending SOAR approval queue via the Infinity plugin against `soc/api.py`
(run the API before opening those panels).

## Boss of the SOC replay

```bash
# download BOTS v3 separately (https://github.com/splunk/botsv3), then:
python generator/bots_convert.py --input /path/to/botsv3.json --limit 50000
```

Maps Sysmon/stream:ip/O365 sourcetypes into our JSONL format and retimes the
2018 timestamps to now (relative spacing preserved) so Loki accepts them.

## Later (not in POC)

- Real SOAR execution at the `simulated-executed` point in `soc/api.py`
- Batch JEV requests / Alloy-native webhook consumer instead of Loki polling
