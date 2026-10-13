# LabTrace — Explainable Access Alerts

**Cyber Hack Hackathon project**

LabTrace turns shared-lab login event CSVs (or JSON) into an **explainable review queue**.  
It flags clear patterns for human review — it never locks accounts, never blocks users, and never accuses anyone.

> **Explain everything. Accuse no one. Block nothing.**

---

## Features

| Capability | Description |
|------------|-------------|
| **R1** | Failure burst then success (same account + computer) |
| **R2** | Successful login outside lab hours / non-working day |
| **R3** | Cross-computer activity (same account on ≥2 machines in a window) |
| **R5** | Failure burst with **no** success (brute-force candidate) |
| Multi-dataset | Upload multiple files; switch and review any previous dataset |
| Smart import | CSV + JSON, column alias auto-detect, interactive mapping |
| Evidence-to-Action | Why flagged, event timeline, recommended next checks |
| 100% client-side | Nothing leaves the browser |

---

## Quick start

1. Open **`labtrace.html`** in any modern browser (Chrome, Edge, Firefox).
2. Sign in with demo credentials:
   - **Lab Assistant:** `lab.assistant` / `LabTrace@2026`
   - **Supervisor:** `lab.supervisor` / `Supervisor@2026`
3. Click **Load sample data** or **Upload CSV / JSON**.
4. Explore **Dashboard**, **Cases**, **Datasets**, **Analytics**, and **Help**.

No server or install required.

---

## Sample files (for testing)

| File | Purpose |
|------|---------|
| `labtrace-sample.csv` | Main sample — R1, R2, R3, R5, Priority, Routine |
| `labtrace-sample-2.csv` | Second dataset — test multi-dataset switching |
| `labtrace-sample.json` | JSON import test |
| `labtrace-alt-headers.csv` | Alternate column names — tests mapping dialog |
| `labtrace-template.csv` | Minimal valid CSV template |

**Suggested test flow**

1. Upload `labtrace-sample.csv` → inspect Priority / Review / Investigate cases.  
2. Upload `labtrace-sample-2.csv` → open **Datasets** and switch back to the first.  
3. Upload `labtrace-sample.json`.  
4. Upload `labtrace-alt-headers.csv` and complete the column mapping.

---

## CSV format

Required fields (names are flexible; mapping is offered when headers differ):

```text
event_id,timestamp,account,computer,event,department_case
```

- **timestamp:** `YYYY-MM-DD HH:MM:SS`
- **event:** `FAILED` or `SUCCESS`
- **department_case:** context only (not used by detection rules)

JSON: array of objects with the same keys (or common aliases).

---

## Detection rules (summary)

- **R1** — ≥ N failures within W minutes, then success (same account + computer).  
- **R2** — Success outside configured lab open/close times or on a non-working day.  
- **R3** — Same account on ≥ 2 computers within the cross-computer window (default 30 min).  
- **R5** — ≥ N failures within W minutes with **no** subsequent success.  

Labels: **Priority Review** · **Review** · **Investigate** · **Routine** (with a clear reason).

All thresholds (N, W, hours, working days, cross-computer window) are adjustable in **Settings**.

---

## Privacy & design principles

- All processing runs in the browser. No data is sent to a server.
- LabTrace only prioritizes human review. It never blocks, locks, or disables accounts.
- Every decision is explainable; routine cases also get a specific “why not flagged” reason.

---

## Project structure

```text
labtrace.html              # Full single-file app (UI + engine)
labtrace-sample.csv        # Primary sample data
labtrace-sample-2.csv      # Second dataset for multi-upload demo
labtrace-sample.json       # JSON sample
labtrace-alt-headers.csv   # Alternate headers for mapping test
labtrace-template.csv      # Minimal template
README.md                  # This file
```

---

## License / hackathon note

Built for the Cyber Hack Hackathon. Demo credentials and sample data are synthetic and for demonstration only.
