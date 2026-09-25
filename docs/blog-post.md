# Your Logs Don't Need an LLM. They Need a Reflex.

### Building a SOC triage agent on a System 1 model — and what it teaches us about the future of classification

---

Every security operations center drowns in the same arithmetic: thousands of log events per minute, each one a tiny classification problem — *malicious or benign? which attack tactic? how severe?* — and a vanishingly small fraction that deserve expensive human (or machine) reasoning.

For the last two years, the default answer to "classify this thing with AI" has been an LLM. You know the pattern: stuff the item into a prompt, beg for JSON, parse the output, hope the model's confidence is real. It works, but it's the computational equivalent of consulting a philosophy professor to sort your mail. A single gpt-4o-mini classification call costs ~450ms and real money at log volume; worse, when you ask an LLM "how sure are you?", the number it gives you is a *verbalized opinion*, not a calibrated probability. There is no mathematical reason `0.8` from a chat model means the thing is true 80% of the time.

Meanwhile, the entire field of agent engineering has converged on a different insight: the agent loop is expensive because *every decision* — routing, gating, triaging — goes through a generative model. LangChain's recent post on [building a harness with JEV](https://www.langchain.com/blog/building-a-harness-with-jev) put a name on the alternative: **System 1 models**.

## What a System 1 model actually is

The name is a deliberate Kahneman reference. Human System 1 thinking is fast, automatic, pattern-matching; System 2 is slow, deliberate, effortful. TypeSafe AI's **JEV** applies that split to models. JEV is *not* an LLM. It generates no text, produces no reasoning trace, and cannot be chatted with. Instead, you send it a **state** (any context) and a set of typed **questions**, and it returns typed answers with calibrated probabilities, trained via reinforcement learning for calibrated decisions (RLCD):

- **Noul** — does this condition hold? → probability of yes
- **Choice** — which of these options? → probability for *every* option + confidence
- **Score** — where on this ordered scale? → probability-weighted position + per-level distribution + confidence

Three properties make this a categorically different tool than prompt-and-parse:

1. **Calibrated probabilities.** When JEV says `0.94`, you can build `if p > 0.9: escalate` and *mean it*. This is the difference between a probability and a vibe.
2. **Parallel questions.** Every question in a request is evaluated simultaneously and independently. Asking four questions costs barely more than asking one.
3. **Speed and cost.** TypeSafe reports up to 200x faster inference and 400x lower cost than comparable LLMs on classification tasks. JEV is now on [OpenRouter](https://openrouter.ai/typesafe/jev-1.13) (`typesafe/jev-1.13`) via their Decisions API, so one API key runs an entire hybrid stack.

The catch: JEV can't explain itself, can't correlate across events, can't write an incident report. Which is exactly why the interesting architecture is a *hybrid* — System 1 as a reflex layer on the hot path, an LLM as the deliberative layer behind it. We built that architecture for the SOC problem, and it's worth walking through what it looks like and what we measured.

## The architecture: a reflex layer and a deliberative layer

```
 synthetic attack ──▶ Grafana Alloy ──▶ Loki ──▶ SYSTEM 1: JEV (per event)
 (phishing→exec→persist→privesc        │          4 questions, one request:
  →lateral→exfil + benign noise)       │          is_suspicious? MITRE tactic?
                                        ▼          severity? needs_context?
                                   Grafana    policy: escalate / review / benign
                                                       │ escalate
                                                       ▼
                                            SYSTEM 2: LLM correlator
                                            campaign clustering → narrative
                                            → SOAR playbook → JEV guardrail
                                            → human approval queue
```

**Ingestion** is boring on purpose: Grafana Alloy tails log files into Loki. Nothing about the System 1 layer requires changing how logs are collected — it sits *behind* your existing pipeline as a consumer.

**System 1 (the reflex)** polls Loki and classifies every event. Crucially, the `state` JEV sees isn't the raw log line — it's the log line **plus injected context**: the asset's criticality, the user's role and admin status, and how many events involving this host/user were already escalated in the last 20 minutes. A PowerShell launch and a PowerShell launch *on a domain controller by a finance user 6 minutes after a foreign login* are different states, and a stateless classifier can't tell them apart. Context injection is where classification quality is actually won.

For each enriched event, JEV answers four questions in one parallel request: `is_suspicious` (Noul), `mitre_tactic` (Choice over 10 ATT&CK tactics), `severity` (Score 1–5), and `needs_context` (Noul — "is this event only meaningful as part of a sequence?", which catches mid-kill-chain events like registry Run-keys that look tame alone).

Routing is then pure policy over calibrated outputs — no LLM involved:

- **escalate** if `p(suspicious) ≥ 0.9`, or `severity ≥ 3 and p ≥ 0.7`, or **confidence is low** (a calibrated model near 0.5 is *telling you it doesn't know* — the safe move is to escalate), or the event is context-dependent and moderately suspicious
- **benign** only on high-confidence, low-severity, low-suspicion agreement
- everything else falls to a cheap **review** queue

**System 2 (the deliberative layer)** only ever sees what the reflex escalates. It clusters escalated events by host/user anchors in a sliding window, declares a **campaign** when ≥3 distinct MITRE tactics (or ≥5 events) converge on one anchor, stitches overlapping campaigns together, and hands the full event history to an LLM for the things LLMs are genuinely good at: writing the incident narrative and proposing a containment playbook.

**The guardrail** is the pattern we like most. Every proposed SOAR action ("isolate WS-104", "reset alice's credentials") is gated through JEV before reaching the human approval queue, with a single Noul: *"could this action disrupt legitimate business operations if the detection were a false positive?"* — the same Auto Mode pattern the LangChain post describes for gating agent tool calls. System 1 watches System 2. Actions JEV scores as disruptive are force-marked high-risk; nothing executes without human approval.

**Observability** treats the models as first-class infrastructure: every call — System 1, System 2, guardrail — is traced to Phoenix (OpenTelemetry/OpenInference) with full request/response payloads, and JEV's complete probability maps stream into Loki next to the raw logs. You can watch the classifier think: for one benign event, JEV returned `p(suspicious)=0.28`, `p(needs_context)=0.78`, severity 1.4, and a tactic distribution smeared across execution/persistence rather than spiked — visible uncertainty, not a hidden coin flip.

## What we measured

We replayed a synthetic multi-stage intrusion (TOR-exit Okta login → Word macro → encoded PowerShell → Run-key persistence → LSASS access → SMB pivot → PsExec → staged DLL → 512MB exfiltration) interleaved with ~120 benign noise events:

| Layer | Calls | Avg latency | Total cost | Cost/call |
|---|---|---|---|---|
| **System 1 (JEV)** | 139 | **191 ms** | **$0.0052** | $0.000037 |
| System 2 (gpt-4o-mini) | 9 | 3,657 ms | $0.0029 | $0.00033 |
| Guardrail (JEV) | 36 | 221 ms | $0.0005 | $0.000014 |

The entire demo — classifying every log line, detecting the campaign, generating narratives and playbooks, gating every action — cost **under two cents**. The reflex layer classified ~140 events for what a *single* mid-tier LLM call costs. And note the latency split: JEV answered four typed questions in ~190ms while the LLM needed ~3.7s to reason over a campaign — a 19x gap that is the whole point of the architecture. System 2 made 9 calls because System 1 made 139; without the reflex layer, the LLM bill and latency would scale with log volume instead of with *incident* volume.

Detection worked: the campaign was correctly assembled around the `alice`/`WS-104` anchor with five distinct tactics, cross-stitched with the `SRV-02`/`admin` pivot, and the playbook (isolate host → reset credentials → block exfil IP) was sensible and properly gated.

## Honest lessons

**Classification quality lives in the question design and the state, not the model.** Our first question set worked, but JEV flagged some benign firewall noise as exfiltration, which briefly spun up a false-positive campaign on a quiet host. The fix isn't a bigger model — it's sharper criteria ("exfiltration = *large or unusual* outbound transfer to a *rare* destination"), richer enrichment (bytes-out baselines per host), and thresholds tuned on labeled data. Calibrated probabilities make this tuning a data problem instead of a prompt-engineering seance: pick thresholds from the cost of each mistake type, not from round numbers.

**Low-confidence routing is the killer feature nobody demos.** Because JEV's probabilities mean something, "escalate when unsure" is a principled policy, not a hack. An LLM that outputs `confidence: 0.6` in JSON is roleplaying; a calibrated model near 0.5 is reporting genuine epistemic uncertainty, and a SOC pipeline can route on it.

**System 2 narratives are only as good as their input window.** An early version generated campaign narratives from only the newest event batch, producing a report about "benign explorer.exe activity" for a five-tactic intrusion. Reasoning layers need the full accumulated state; reflexes don't.

**No reasoning trace is a feature.** JEV can't explain its answers, which initially feels like a limitation for a SOC. In practice it forces the right architecture: the probability map *is* the audit artifact for classification, and when you need prose, that's a separate, deliberate System 2 job — possibly triggered precisely by a low-confidence System 1 answer.

## The broader pattern

Strip away the SOC specifics and this is a template for any high-volume classification problem: support ticket triage, content moderation, model routing, agent permission gating, document tagging. The traditional LLM approach spends generative capacity on decisions that don't require generation. A System 1 model collapses the prompt-and-parse step into a typed, calibrated, parallelized decision that costs fractions of a cent and returns in ~200ms — and its outputs are boring, branchable integers and floats your code can trust.

The LLM doesn't disappear. It moves up the stack to where open-ended reasoning, correlation, and language actually earn their cost — and it gets a calibrated reflex layer in front of it deciding what's worth its attention, and a calibrated guardrail behind it checking its impulses.

Fast reflexes, slow thoughts. It worked for cognition; it works for pipelines.

---

*The full POC — Loki/Alloy ingestion, JEV classification layer, System 2 campaign correlator, guardrailed SOAR approval queue, Phoenix tracing, and Grafana dashboards — is open and reproducible in this repository. Bring one OpenRouter API key; the whole demo costs less than a gumball.*
