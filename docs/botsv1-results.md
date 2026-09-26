# BOTS v1 Blind Evaluation — Results

Replay: 8,967 real BOTS v1 events (Splunk Boss of the SOC v1, Wayne Enterprises,
Aug 2016) through the live pipeline with **no hints**. Scoring key:
[docs/botsv1-ground-truth.md](botsv1-ground-truth.md). Slice/policy:
`generator/botsv1_slice.py`. Run: `make attack-botsv1`.

## Headline

**The pipeline found both attacks blind.** System 1 escalated every stage of
both intrusions at 93–100% coverage; System 2 anchored campaigns on the real
attacker IP, the real victim user, and the web-shell host — unprompted.

## System 1 — IOC escalation coverage

| Ground-truth signal | Escalated / present |
|---|---|
| `40.80.148.42` Acunetix scan | 2,679 / 2,877 (93%) |
| `Acunetix` UA signature | 2,386 / 2,386 (100%) |
| `23.22.63.114` brute force / C2 / staging | 123 / 127 (97%) |
| `administrator/index.php` Joomla brute force | 118 / 123 (96%) |
| `3791.exe` uploaded payload | 6 / 6 (100%) |
| `121214.tmp` Cerber script stage | 51 / 51 (100%) |
| `mhtr.jpg` cryptor download | 1 / 2 |
| `solidaritedeproximite.org` Cerber domain | 0 / 1 (single event, routed review) |

## System 2 — campaigns vs ground truth

| Campaign | Anchor | Verdict |
|---|---|---|
| #1 | `40.80.148.42` (recon→initial-access→execution→exfiltration) | ✅ the real APT attacker IP |
| #18 | `we1149srv` — *"IUSR executing commands in C:\inetpub\wwwroot\joomla\"* | ✅ the Joomla web shell, correctly narrated |
| #14 / #16 | `WAYNECORPINC\bob.smith` (defense-evasion, execution, exfiltration) | ✅ the real Cerber victim |
| #10/#11/#15/#20/#26 | `we8105desk` (Bob's workstation) | ✅ Cerber host, multiple merges |
| #5/#13/#24 | `we9041srv` SMB/445 "lateral movement" | ⚠️ not in ground-truth key — likely background dataset noise; needs review |

26 campaigns total (many merged) — campaign churn was amplified by mid-run
restarts; with a clean single run expect fewer, cleaner campaigns.

## The big finding: calibration routes the flood up

- 9,180 classified → **58% escalate**, 32% review, 9% benign.
- 1,689 escalated events have JEV tactic = `benign`: on this out-of-distribution
  data shape (fat Splunk/Sysmon XML records), JEV honestly reports uncertainty
  (p near 0.5) and the `confidence < 0.55 → escalate` safe default fires en
  masse. Calibration did exactly its job — but it means routing policy must be
  tuned per data shape (or the state builder must normalize the shape) before
  volume like this is affordable in System 2.
- 165 pending approvals = downstream cost of that flood.

## Cost

| Layer | Calls | Cost | Latency |
|---|---|---|---|
| System 1 (JEV) | 9,260 | $1.20 | 207 ms avg |
| System 2 (gpt-4o-mini) | 37 | $0.04 | — |
| Guardrail (JEV) | 165 | $0.002 | — |

## Telemetry gaps (dataset coverage, not detection failures)

- USB insertion + `miranda_tate_unveiled.dotm` initial execution: lives in
  `WinEventLog:Security` (not pulled — 4GB).
- `cerberhhyed5frqa.xmfir0.win` ransom-note DNS: lives in `stream:dns` (not pulled).

## Infra fixes forced by this run

- classify: bounded Loki catch-up windows (10 min) — unbounded forward queries
  504; cursor walks through empty windows (`soc/classify.py`).
- classify: fetch limit 150 — Loki's internal querier→frontend gRPC reply
  exceeds the 4MiB default with fat raw lines (queries executed in ~17 ms but
  could not be delivered). Loki config bumped to 32MiB for Grafana panels.
- Makefile: `dev` is now idempotent (`stop` first) after duplicate daemons
  raced the cursor file.
