# System Architecture

```mermaid
flowchart TB
    subgraph Sources
        G[generator/campaign.py<br/>synthetic APT + noise]
        B[BOTS v3 replay<br/>bots_convert.py]
    end

    subgraph Platform["Log platform (docker compose)"]
        AL[Alloy<br/>loki.source.file]
        LO[(Loki)]
        GF[Grafana :3000]
        PH[Phoenix :6006<br/>OTel traces]
    end

    subgraph S1["System 1 — reflex (soc/classify.py)"]
        EN[enrich.py<br/>YAML + SQLite counts]
        JV[[JEV typesafe/jev-1.13<br/>4 questions, 1 request]]
        PO[thresholds.yml<br/>routing policy]
        EN --> JV --> PO
    end

    subgraph S2["System 2 — deliberative (soc/correlate.py)"]
        CL[cluster by host/user<br/>20-min window]
        CP[campaign detect<br/>≥3 tactics or ≥5 events]
        LL[[LLM gpt-4o-mini<br/>narrative + playbook]]
        GD[[JEV guardrail<br/>disruption Noul per action]]
        CL --> CP --> LL --> GD
    end

    DB[(SQLite<br/>events · campaigns<br/>approvals · model_calls)]
    API[FastAPI :8000<br/>approval queue]

    G & B --> AL --> LO
    LO -->|poll 5s| EN
    PO -->|all decisions| DB
    PO -->|escalate| CL
    S2 --> DB
    GD --> API
    DB --> API
    API --> GF
    LO --> GF
    S1 & S2 -.OTLP.-> PH
    S1 & S2 -.agent.log.-> AL

    style JV fill:#7c2d12,stroke:#fb923c,color:#fff
    style LL fill:#1e3a8a,stroke:#60a5fa,color:#fff
    style GD fill:#7c2d12,stroke:#fb923c,color:#fff
```

Cost/latency asymmetry (measured): JEV 191 ms / $0.000037 per event vs.
LLM 3.7 s / $0.00033 per campaign — System 2 cost scales with *incidents*,
not log volume.
