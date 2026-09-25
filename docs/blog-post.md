# System 1 Models for High-Volume Security Classification: A Hybrid SOC Pipeline

**Abstract.** LLM-based log triage does not scale: every classification costs a full generative call, and verbalized confidence scores are not calibrated probabilities. We replace the per-event classifier with JEV, a System 1 decision model (TypeSafe AI), reserving an LLM for cross-event correlation and response planning. The resulting pipeline classifies events in 191 ms at $0.000037/call — 19x faster and ~9x cheaper per decision than the LLM path — while keeping total end-to-end cost of a full attack-detection demo under $0.02.

## 1. Problem

SOC triage is a high-volume classification workload. Each log event requires labels (malicious?, MITRE tactic, severity) and a routing decision. Two properties make chat LLMs the wrong tool:

1. **Cost/latency per decision.** Prompt-and-parse classification is a generative call: ~450 ms+ and non-trivial cost, multiplied by every log line.
2. **Uncalibrated confidence.** An LLM emitting `"confidence": 0.8` in JSON produces a verbalized estimate with no guarantee that 80% of such cases are correct. Downstream thresholds (`p > 0.9 → escalate`) are meaningless without calibration.

## 2. Background: System 1 models

JEV is not an LLM; it generates no text. It takes a **state** (context) and typed **questions**, returning typed answers trained via reinforcement learning for calibrated decisions (RLCD):

| Primitive | Returns |
|---|---|
| Noul (yes/no) | probability of true |
| Choice (1-of-N) | probability per option + confidence |
| Score (ordinal scale) | weighted position + per-level distribution + confidence |

Questions in one request are evaluated in parallel; marginal cost per extra question is small. Reported gains: up to 200x faster, 400x cheaper than LLM classification. We access JEV via OpenRouter's Decisions API (`typesafe/jev-1.13`), so one API key serves both model classes.

Calibration is the load-bearing property: `p` near 0.5 denotes genuine epistemic uncertainty and is itself a routing signal (Section 4.2).

## 3. Architecture

```
logs ─▶ Alloy ─▶ Loki ─▶ System 1: JEV classify(enriched event)
                              │ 4 questions / 1 request
                    policy: escalate | review | benign
                              │ escalate
                              ▼
                    System 2: LLM — cluster → campaign →
                    narrative → playbook → JEV guardrail →
                    human approval queue
```

- **Ingestion:** Grafana Alloy tails JSONL sources (Okta, Sysmon, firewall) into Loki. The classifier is a Loki consumer; no changes to log shipping.
- **System 1:** polls Loki (5 s cursor), enriches each event (asset criticality, user role/admin, count of recent escalations for host/user), classifies, applies policy, stores verdicts (SQLite).
- **System 2:** clusters escalations by host/user anchor over a 20-min window; declares a *campaign* at ≥3 distinct tactics or ≥5 events per anchor; merges overlapping campaigns; an LLM (gpt-4o-mini) produces the narrative and containment playbook from full campaign history (capped at 50 events).
- **Guardrail:** each proposed action is gated by a JEV Noul ("could this action disrupt legitimate operations if the detection is a false positive?"); p > 0.7 forces risk=high. All actions require human approval (simulated execution).
- **Observability:** all model calls logged with full request/response, latency, `usage.cost` (SQLite → REST API → Grafana); mirrored to Loki as `job="soc-agent"`; OpenTelemetry/OpenInference traces to Phoenix with per-event and per-campaign span trees.

## 4. Design decisions

### 4.1 Question set (per event, one parallel request)

| Question | Type | Purpose |
|---|---|---|
| `is_suspicious` | Noul | primary routing signal |
| `mitre_tactic` | Choice(10) | ATT&CK tactic |
| `severity` | Score(1–5) | ordinal severity |
| `needs_context` | Noul | flags sequence-dependent events |

`needs_context` targets mid-kill-chain events (e.g., registry Run-key writes) that appear benign in isolation.

### 4.2 Routing policy

```
escalate: p(susp) ≥ 0.9
        | severity ≥ 3 ∧ p(susp) ≥ 0.7
        | confidence < 0.55          # calibrated uncertainty → safe default
        | p(needs_context) ≥ 0.8 ∧ severity ≥ 2.5 ∧ p(susp) ≥ 0.5
benign:   severity ≤ 2 ∧ p(susp) < 0.3 ∧ confidence ≥ 0.8
default:  review
```

Confidence for Nouls is derived as `|p − 0.5| · 2`. The low-confidence rule trades System 2 cost for recall on novel inputs; all parameters are YAML-tunable.

### 4.3 Context injection

The state sent to JEV includes host criticality, user role, and rolling escalation counts. Classification quality is determined primarily by state construction and question criteria, not model capacity (Section 6).

## 5. Evaluation

Workload: synthetic 10-stage intrusion (TOR-exit login → macro → encoded PowerShell → Run-key persistence → LSASS access → SMB pivot → PsExec → DLL staging → 512 MB egress) interleaved with ~120 benign events.

| Layer | Calls | Avg latency | Total cost | Cost/call |
|---|---|---|---|---|
| System 1 (JEV) | 139 | 191 ms | $0.0052 | $0.000037 |
| System 2 (gpt-4o-mini) | 9 | 3,657 ms | $0.0029 | $0.00033 |
| Guardrail (JEV) | 36 | 221 ms | $0.0005 | $0.000014 |

Results:

- Attack chain correctly assembled: campaign anchored on `alice`/`WS-104` with 5 tactics; pivot campaign on `SRV-02`/`admin`; duplicate anchors merged.
- Playbook actions (isolate host, reset credentials, block egress IP) generated, guardrail-gated (e.g., "full forensic analysis" scored p(disruptive)=0.77), and queued for approval.
- System 2 invocation count (9) decouples from event volume (139+); cost scales with incidents, not logs.
- JEV's per-option probability maps (e.g., tactic distribution over 10 tactics per event) are retained as audit artifacts.

## 6. Limitations and lessons

- **False positives from criteria, not capacity.** Benign firewall noise labeled as exfiltration produced one spurious campaign. Mitigation: sharper criteria (volume/rarity thresholds), per-host egress baselines in enrichment, threshold tuning on labeled data — calibration makes this a data exercise rather than prompt iteration.
- **Narrative state window.** System 2 must reason over full campaign history; reasoning over only the latest batch produced incorrect narratives.
- **No reasoning traces.** JEV returns probabilities only. We treat the probability map as the classification audit record and delegate prose to System 2, triggered optionally by low System 1 confidence.
- **Emulated fallback caveat.** An LLM approximating the question interface produces uncalibrated probabilities; thresholds must be re-tuned per backend.

## 7. Conclusion

For classification on hot paths, a calibrated decision model should sit in front of generative models: System 1 for per-item typed judgments with probabilities code can branch on, LLMs for cross-item reasoning and language. The pattern generalizes to ticket triage, moderation, model routing, and agent tool-call gating. In our pipeline the division is explicit: 139 fast calibrated judgments, 9 slow deliberative calls, and a guardrail between System 2's proposals and action.

---

*Code: this repository. One OpenRouter key runs both model classes; full demo cost < $0.02.*
