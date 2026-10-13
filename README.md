# LabTrace SOC — Live Real Event Ingestion & Threat Analysis

> **Explain everything. Accuse no one. Block nothing without supervisor sign-off.**

LabTrace SOC transforms raw Windows and Linux authentication events into an explainable, prioritized incident review queue.

---

## 🏗️ Architecture

```
┌─────────────────────────────────┐
│          Log Sources            │
│  - Windows PC (Events 4624/4625)│
│  - Domain Controller            │
│  - Linux VM / Public Honeypot   │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│           Collectors            │
│  - windows-collector.ps1        │
│  - linux-collector.sh           │
└────────────────┬────────────────┘
                 │ HTTP POST JSON (API Key)
                 ▼
┌────────────────────────────────────────────────────────┐
│               LabTrace Ingest Server (:3000)           │
│  - Noise reduction (drops $, maps logon types)         │
│  - Server-side GeoIP & Threat Reputation Enrichment    │
│  - Cryptographic SHA-256 Hash-Chained Audit Ledger     │
│  - SQLite Event Persistence (rolling 24h retention)    │
│  - Supervisor-authorized Playbook Endpoints            │
└────────────────┬───────────────────────────────────────┘
                 │ Server-Sent Events (SSE /api/stream)
                 ▼
┌────────────────────────────────────────────────────────┐
│               LabTrace SOC Browser UI                  │
│  - Live Auth Stream with Real Timestamps & IPs         │
│  - MITRE ATT&CK Matrix & Threat Gauge                  │
│  - Real SLA Age Tracking (Date.now() - c.startTs)      │
│  - Supervisor Playbook Modal (Lock, Isolate, Escalate) │
│  - Audit Chain Verification (100% Cryptographic Check) │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Running the App)

### 1. Start the Ingest & Web Server
```powershell
cd C:\Users\sivas\.gemini\antigravity\scratch\labtrace-soc
node server.js
```
The server will start at:
* **Web Application:** `http://localhost:3000`
* **SSE Stream:** `http://localhost:3000/api/stream`
* **Ingest Webhook:** `POST http://localhost:3000/api/ingest`

### 2. Login Credentials
* **Supervisor:** `lab.supervisor` / `Supervisor@2026` (Has sign-off and containment authorization)
* **Lab Assistant:** `lab.assistant` / `LabTrace@2026` (Triage and review)
* **SSO:** One-click Entra ID / Google Workspace mock login

---

## 📡 Feeding Real Events

### Option A: Windows PC or Domain Controller (Event IDs 4624 & 4625)
Open PowerShell (as **Administrator** for Security log read access) and run:
```powershell
cd C:\Users\sivas\.gemini\antigravity\scratch\labtrace-soc\collectors
.\windows-collector.ps1 -ServerUrl http://localhost:3000/api/ingest
```
*Note: If run without Administrator rights, the collector automatically falls back to `-Mode Test` to demonstrate the event stream without permission errors.*

### Option B: Linux VM or Cloud Honeypot (SSH Brute Force)
Deploy on an internet-facing Linux VPS with SSH port 22 exposed:
```bash
export SERVER_URL=http://YOUR_SERVER_IP:3000/api/ingest
sudo bash collectors/linux-collector.sh
```
Within minutes, internet bots attempting credential guessing on port 22 stream into LabTrace as real brute force, password spray, and Tor exit events!

### Option C: Simulated Real-World Feeder
To test realistic traffic immediately (including Tor exit nodes, scanners, and MITRE attack patterns):
```powershell
npm run feeder
```

---

## 🛡️ Key Features Implemented

| Feature | Implementation Details |
|---|---|
| **Real Live Feed** | Browser connects to `/api/stream` via native `EventSource`. Deduplicates events and keeps a rolling memory window. |
| **Noise Reduction** | Server discards machine accounts (`*$`), filters system accounts, and categorizes Windows logon types (Interactive 2, RDP 10, Network 3). |
| **Enrichment** | Resolves real GeoIP (country, city, flag) and threat intelligence (Tor exit nodes, known scanners) on the server. Cached to protect API keys. |
| **SLA Tracking** | Real event age calculated from `Date.now() - c.startTs`. P1 Priority breached after 15 min; P2 Review breached after 60 min. |
| **Supervisor Playbooks** | Lock and Isolate require supervisor authorization and confirmation note. Enforces "never block without approval" principle. |
| **Audit Ledger** | Every decision is stored in SQLite and linked via a cryptographic SHA-256 hash chain (`prev_hash` -> `hash`). Verify button in the UI verifies 100% chain integrity. |
| **Server Persistence** | Built-in `node:sqlite` database (`data/labtrace.db`) with automatic 24-hour retention pruning. |

---

## 📂 Project Structure

```
labtrace-soc/
├── server/
│   ├── db.js             # SQLite database layer using node:sqlite
│   ├── noise.js          # Machine account ($) filter & logon type analyzer
│   ├── enrichment.js     # GeoIP & threat reputation cache
│   ├── audit.js          # SHA-256 cryptographic hash-chained audit ledger
│   ├── playbooks.js      # Supervisor-approved playbook actions
│   └── auth.js           # Salted password authentication & session management
├── collectors/
│   ├── windows-collector.ps1  # Real Windows Security Event Log collector
│   ├── linux-collector.sh     # Linux auth.log SSH honeypot collector
│   └── test-feeder.js         # Realistic background traffic generator
├── public/
│   └── index.html        # Single-page Cyber-SOC interface with real SSE feed
├── server.js             # Express ingest server & SSE broadcaster
└── package.json
```
