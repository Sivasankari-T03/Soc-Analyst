# LabTrace — Explainable Access Alerts

**Cyber Hack Hackathon · single-operator SOC-style review for shared lab logins**

LabTrace turns login event CSVs/JSON into an **explainable review queue** with **risk scores (0–100)** and a **facts-only AI risk summary**.

It never locks accounts, never blocks users, and never invents evidence.

> **Explain everything. Accuse no one. Block nothing.**

---

## Login (single Admin)

| Username | Password | Role |
|----------|----------|------|
| `admin` | `LabTrace@2026` | Admin |

One operator reviews all cases (no separate assistant/supervisor roles).

---

## Features

- **Rules R1–R7:** burst→success, after-hours, cross-computer, slow-burn, failures without success, password spray  
- **Risk score + band** (Critical / High / Medium / Low) with transparent breakdown  
- **AI risk summary** — restates facts only; does not invent events  
- Multi-dataset history, CSV/JSON import, column mapping  
- Cyber-themed dark UI, fully client-side  

---

## Own data (no PS2 / external contest dataset)

Contest rules: teams must **source or prepare their own resources**. Do **not** depend on a provided PS2 dataset.

### Recommended approaches

1. **Synthetic lab CSV (recommended for demo)**  
   Write 40–80 rows covering: normal logins, one typo, R1 burst, after-hours, cross-PC, slow fails, spray, invalid timestamp.  
   Use the included `labtrace-sample.csv` as a template, then **customize account/computer names** for your institute story.

2. **Export from a Windows VM you control**  
   Enable Audit Logon events → Event Viewer → Security → filter 4624/4625 → Save as CSV → map columns in LabTrace.

3. **Generate with a small script**  
   Python/`faker`-style script: random accounts, PCs, mix of FAILED/SUCCESS with planted attack windows.

4. **Anonymized institutional logs (if allowed)**  
   Strip personal data; keep only event_id, timestamp, account alias, computer, FAILED/SUCCESS.

### CSV columns

```text
event_id,timestamp,account,computer,event,department_case
```

`timestamp`: `YYYY-MM-DD HH:MM:SS` · `event`: `FAILED` or `SUCCESS`

---

## Quick start

1. Open `labtrace.html` in a browser  
2. Sign in: **admin** / **LabTrace@2026**  
3. Load sample data or upload your CSV/JSON  
4. Review **Risk** column and **AI risk summary** on each case  

---

## Project files

```text
labtrace.html
README.md
labtrace-sample.csv
labtrace-sample-2.csv
labtrace-sample.json
labtrace-alt-headers.csv
labtrace-template.csv
```

---

## Privacy

Everything runs in the browser. Nothing is sent to a server.
