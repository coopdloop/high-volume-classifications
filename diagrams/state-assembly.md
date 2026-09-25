# Per-Event State Assembly (deterministic, no LLM)

Every JEV call is **stateless**. The "context" is constructed in code, from
scratch, for every event — YAML lookups, SQL queries, and string formatting.

```mermaid
flowchart LR
    subgraph Ingestion
        E[Log event<br/>from Loki poll]
    end

    subgraph Code["Context assembly (soc/enrich.py) — pure code"]
        A1[config/assets.yml<br/>host criticality, type, owner]
        A2[config/assets.yml<br/>user role, admin flag]
        S1[("SQLite: escalated events<br/>same host, last 20m")]
        S2[("SQLite: escalated events<br/>same user, last 20m")]
        FMT["f-string template:<br/>LOG EVENT + ENRICHMENT block"]
        A1 --> FMT
        A2 --> FMT
        S1 -->|count| FMT
        S2 -->|count| FMT
    end

    subgraph JEV["JEV (stateless inference)"]
        Q["4 questions in parallel:<br/>is_suspicious · mitre_tactic<br/>severity · needs_context"]
        OUT["typed answers +<br/>calibrated probabilities"]
        Q --> OUT
    end

    E --> FMT
    FMT -->|state: ~900 tokens, flat per call| Q
    OUT --> P[routing policy<br/>escalate / review / benign]

    style JEV fill:#1f2937,stroke:#6b7280,color:#e5e7eb
    style Code fill:#0f3b2e,stroke:#34d399,color:#e5e7eb
```

**Key property:** JEV has no memory between calls. Event #10 and event #10,000
cost the same ~900 input tokens because there is no conversation to grow.
