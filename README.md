# LabTrace — Explainable Access Alerts

**Cyber Hack Hackathon project**

LabTrace turns shared-lab login event CSVs (or JSON) into an **explainable review queue** with **deterministic risk scores** and an **AI risk summary** built only from facts in the data.

It flags clear patterns for human review — it **never locks accounts**, **never blocks users**, and **never accuses anyone**.

> **Explain everything. Accuse no one. Block nothing.**

---

## Features

| Capability | Description |
|------------|-------------|
| **R1** | Failure burst then success (same account + computer) |
| **R2** | Successful login outside lab hours / non-working day |
| **R3** | Cross-computer activity (same account on ≥2 machines) |
| **R4** | Slow-burn repeated failures (many fails over hours, no short burst) |
| **R5** | Failure burst with **no** success |
| **R7** | Password-spray shape (many accounts, few fails each, same host) |
| **Risk score 0–100** | Deterministic score from rules + volume (Critical / High / Medium / Low) |
| **AI risk summary** | Facts-only narrative of why the score is high or low — does **not** invent events |
| Multi-dataset | Upload multiple files; switch and review any previous dataset |
| Smart import | CSV + JSON, column alias auto-detect, interactive mapping |
| Evidence-to-Action | Why flagged, timeline, risk breakdown, recommended checks |
| 100% client-side | Nothing leaves the browser |

---

## AI risk summary

Every case gets:

1. **Risk score (0–100)** — computed only from matched rules and counts (e.g. R1+R2, failure volume, cross-computer hosts).
2. **Risk band** — Critical (≥85), High (≥65), Medium (≥40), Low.
3. **Score breakdown** — transparent list of what added points.
4. **AI risk summary** — short English paragraph that **only restates imported fields and rule outcomes**. It never invents timestamps, accounts, or evidence.

This follows industry “explainable” detectors (SIEM severity, TraceGuard-style rules) while staying fully offline and auditable for a shared lab.

---

## Detection rules (aligned with existing practice)

| Rule | Industry analogue | LabTrace behaviour |
|------|-------------------|--------------------|
| R1 | SIEM / Sumo “Successful Brute Force”, Sigma | ≥ N fails in W min, then success |
| R2 | UEBA / after-hours rules | Success outside lab hours or non-working day |
| R3 | LogonTracer account↔host graph | Same account on ≥2 computers in a window |
| R4 | Slow / distributed brute-force playbooks | Many fails over ≥2 hours without a short burst |
| R5 | Classic brute-force (no success) | ≥ N fails in W min, no success |
| R7 | Password spray detections | ≥5 distinct accounts failing on one host in a short window |

Labels: **Priority Review** · **Review** · **Investigate** · **Routine** (with a clear reason).  
Cases are sorted by **risk score** so the queue surfaces the most important work first.

---

## Quick start

1. Open **`labtrace.html`** in Chrome, Edge, or Firefox.
2. Sign in:
   - Lab Assistant: `lab.assistant` / `LabTrace@2026`
   - Supervisor: `lab.supervisor` / `Supervisor@2026`
3. **Load sample data** or **Upload CSV / JSON**.
4. Open **Cases** → sort by **Risk** or filter **High risk**.
5. Open a case → read **Risk score**, **breakdown**, and **AI risk summary**.

No server install required.

---

## Sample files

| File | Purpose |
|------|---------|
| `labtrace-sample.csv` | R1–R5, R7 spray, R4 slow-burn, Priority, Routine |
| `labtrace-sample-2.csv` | Second dataset (multi-dataset demo) |
| `labtrace-sample.json` | JSON import |
| `labtrace-alt-headers.csv` | Alternate headers → mapping dialog |
| `labtrace-template.csv` | Minimal valid CSV |

---

## CSV format

```text
event_id,timestamp,account,computer,event,department_case
```

- **timestamp:** `YYYY-MM-DD HH:MM:SS`
- **event:** `FAILED` or `SUCCESS`
- **department_case:** context only (not used by rules)

---

## Project structure

```text
labtrace.html              # Full single-file app
labtrace-sample.csv        # Primary sample
labtrace-sample-2.csv      # Second dataset
labtrace-sample.json       # JSON sample
labtrace-alt-headers.csv   # Mapping test
labtrace-template.csv      # Template
README.md                  # This file
```

---

## Privacy & principles

- All processing runs in the browser.
- LabTrace only prioritizes human review. It never blocks or locks accounts.
- AI risk summary is **facts-only** and optional as a narrative layer on top of deterministic scoring.

---

## License / hackathon note

Built for the Cyber Hack Hackathon. Demo credentials and sample data are synthetic.
