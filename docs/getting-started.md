# Getting Started

## What this is

A SOC triage pipeline that puts a **System 1 decision model**
([JEV](https://typesafe.ai/blog/introducing-system-one-models-and-jev)) in
front of an LLM. JEV classifies *every* log event with typed, calibrated
probabilities in ~190 ms for fractions of a cent. An LLM only sees what gets
escalated — it handles correlation, campaign narratives, and response
playbooks, with a JEV guardrail checking its output before a human approves.

- **System 1** (`soc/classify.py`) — poll Loki → enrich → JEV classify → route
- **System 2** (`soc/correlate.py`) — cluster escalations → campaigns → playbook → guardrail → approval queue

## Five-minute setup

```bash
make install   # deps + .env scaffold — then add OPENROUTER_API_KEY to .env
make dev       # platform (loki/alloy/grafana/phoenix) + pipeline daemons
make attack    # fire the synthetic attack (~30s)
make logs      # follow daemon output
```

Then watch:

- classify stdout — live per-event decisions
- Grafana (localhost:3000) — SOC folder: *JEV SOC Agent* (overview), *System 1 Triage*, *Campaigns & Response*, *Logs*; or Explore with `{job="soc"}` / `{job="soc-agent"}`
- Phoenix — LLM traces
- `curl localhost:8000/approvals?status=pending` — human queue

`make stop` to stop daemons, `make down` to stop the platform, `make clean` to wipe data.

### Blind evaluation on real attack data

`make attack-botsv1` replays two real attacks from Splunk's BOTS v1 dataset
(web defacement APT + Cerber ransomware, ~9k events, ~40 min) with **no hints
to the agents**. The scoring key is `docs/botsv1-ground-truth.md` — read it
afterwards to check what the pipeline caught.

## How it scales

The design is cheap-per-event, expensive-per-incident — that's what makes it scale:

1. **Fixed, tiny cost per event.** Every log line costs one ~190 ms JEV call,
   regardless of how bad (or boring) it is. JEV is stateless, so
   `classify.py` replicas can run in parallel against Loki with no
   coordination — scale out by adding workers.
2. **The expensive model is threshold-gated.** The LLM only runs on what
   System 1 escalates, and because JEV's confidence is a *calibrated
   probability*, the routing thresholds in `config/` mean something real —
   turn the dial down when alert volume spikes, up when things are quiet.
3. **Loki is the buffer.** Events land in Loki first; the pipeline polls. A
   burst (like `make attack-burst`) queues up in Loki instead of
   overwhelming the classifiers.
4. **Context is assembled in code, not in the model.** Asset criticality,
   recent escalations, etc. are gathered per event (see
   `diagrams/state-assembly.md`), so scaling context doesn't scale token
   spend.

Net: cost and latency grow with **event volume** on the cheap path and with
**incident count** on the expensive path — never with both at once.

## Where to go next

- `README.md` — overview + layout
- `diagrams/` — architecture, state assembly, feedback loop
- `config/` — thresholds and asset inventory (the "policy" knobs)
- `generator/` — synthetic attack campaign to generate your own traffic
