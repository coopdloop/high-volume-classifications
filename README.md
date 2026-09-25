# High-Volume Classification with System 1 Models

A SOC triage pipeline that puts a **System 1 decision model** ([JEV](https://typesafe.ai/blog/introducing-system-one-models-and-jev))
in front of an LLM. JEV classifies every log event with typed, calibrated
probabilities (~190 ms, fractions of a cent); an LLM only sees what gets
escalated, and handles correlation, narratives, and response playbooks.

Why: LLM classification is slow, expensive per decision, and its "confidence"
isn't a real probability. JEV's is — so routing thresholds actually mean
something. Full writeup: **[docs/blog-post.md](docs/blog-post.md)**.

## How it works

```
logs ─▶ Alloy ─▶ Loki ─▶ System 1: JEV (enrich → classify → route)
                              │ escalate
                              ▼
                    System 2: LLM ─▶ campaign ─▶ playbook
                              └─▶ JEV guardrail ─▶ human approval
```

JEV is stateless — context (asset criticality, recent escalations) is
assembled in code per event. Diagrams: [architecture](diagrams/architecture.md) ·
[state assembly](diagrams/state-assembly.md) · [feedback loop](diagrams/feedback-loop.md)

## Quickstart

```bash
make install   # deps + .env scaffold (then add OPENROUTER_API_KEY to .env)
make dev       # platform + pipeline daemons, one command
make attack    # fire the synthetic attack
make logs      # follow daemon output   ·   make stop / make down / make clean
```

Watch: classify stdout · Grafana Explore `{job="soc"}` / `{job="soc-agent"}` ·
Phoenix traces · `curl localhost:8000/approvals?status=pending`

## Layout

| path | what |
|---|---|
| `soc/classify.py` | System 1: poll Loki, enrich, JEV, route |
| `soc/correlate.py` | System 2: cluster, campaigns, playbook, guardrail |
| `soc/jev_client.py` | backends: JEV via OpenRouter (default), TypeSafe direct, LLM-emulated |
| `config/` | question-adjacent policy: thresholds, asset inventory |
| `generator/` | synthetic attack campaign + BOTS v3 converter |
| `diagrams/`, `docs/` | mermaid diagrams, technical writeup |

Lint mermaid before pushing: `make lint`
