# The Memory Is in SQLite, Not the Model

Cross-event awareness comes from a feedback loop implemented in **code**:
past routing decisions are re-injected into future states. JEV never "sees"
the sequence — it sees a different state string.

```mermaid
sequenceDiagram
    autonumber
    participant L as Loki
    participant C as classify.py (code)
    participant DB as SQLite
    participant J as JEV (stateless)

    L->>C: event N — Okta login, TOR exit IP, user=alice
    C->>DB: count escalations (alice, 20m) → 0
    C->>J: state {raw log, "0 prior escalations"} + questions
    J-->>C: p(susp)=0.93, tactic=initial-access
    C->>DB: insert decision = ESCALATE

    L->>C: event N+1 — powershell -enc, host=WS-104, user=alice
    C->>DB: count escalations (alice, WS-104, 20m) → 1
    C->>J: state {raw log, "1 prior escalation"} + questions
    J-->>C: p(susp)=0.97, tactic=execution
    C->>DB: insert decision = ESCALATE

    Note over J: No memory of event N.<br/>Same model, same weights,<br/>different input string.
```

```mermaid
flowchart TD
    EVN["event N<br/>p(susp) = 0.93 → ESCALATE"] --> DB[(SQLite<br/>escalation counts)]
    DB --> CTX["build_state() for event N+1:<br/>'escalated events involving this host: 1'"]
    CTX --> EVN1["event N+1 evaluated<br/>against richer state"]
    EVN1 --> DB

    style DB fill:#3b2f0f,stroke:#fbbf24,color:#e5e7eb
```

**Design line:** deterministic context assembly in code → calibrated point
judgment from JEV → deliberative cross-event reasoning from the LLM (System 2).
Correlation across the full window is deliberately *not* JEV's job.
