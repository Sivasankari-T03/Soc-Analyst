# LabTrace SOC — Central Ingest Server & Authorized Live Monitoring

> **Explain everything. Accuse no one. Block nothing automatically without supervisor sign-off.**  
> *A human-centered Security Operations Center (SOC) platform for authorized academic and enterprise cybersecurity lab environments.*

---

## 1. Overview & Architecture

LabTrace SOC transforms your Windows laptop into a **centralized SOC server** for an authorized cybersecurity lab network. Connected lab devices stream authentication security events to your laptop over the local area network (LAN).

The server validates, normalizes, analyzes, stores, and presents these events in real time across the **Live SOC Dashboard**, **Case Review Queue**, **Analytics Suite**, and **Defense Lab**.

```
[ Authorized Endpoints ]
  * Windows Device (windows-collector.ps1)
  * Linux / macOS Device (agent.py)
  * In-App Attack Simulator / Replay Demo
         │
         ▼ (HTTP POST /api/ingest + x-api-key)
┌────────────────────────────────────────────────────────┐
│  LabTrace SOC Central Server (Node.js 0.0.0.0:3000)     │
│  ├── Ingestion Controller (Rate-limited, Deduped)      │
│  ├── SQLite WAL Database (Events, Agents, Cases)       │
│  ├── Rule-Based Detection Engine (R1 – R6)             │
│  ├── SHA-256 Cryptographic Audit Ledger                │
│  └── Server-Sent Events (SSE) Broadcast Feed           │
└────────────────────────────────────────────────────────┘
         │
         ▼ (Real-Time SSE Stream /api/stream)
[ Browser Dashboard (HTML5 / Vanilla JS / SVG) ]
  ├── 3D Cybernetic Canvas Login Screen
  ├── Operational Dashboard & KPI Summary
  ├── Clean Incident Review Queue (Expandable Forensics)
  ├── Live SOC Command Center (Playbook Actions: Lock/Isolate/Reset/Escalate)
  ├── Live Security Analytics (Ingestion Trends & Category Split)
  ├── Defense Lab (Auto-Containment, Honeytokens, Motion Bar Chart, Reports)
  └── Tamper-Evident SHA-256 Audit Ledger
```

### Core Principles & Security Boundaries (ENG-02 Compliant)
- **Authorized Opt-In Only:** Physical connection to Wi-Fi never implies authorization to monitor. Endpoints require explicit opt-in and authentication.
- **Privacy Preserving:** Collects strictly authentication metadata (Windows Event IDs 4624 & 4625). **Never collects passwords, keystrokes, personal messages, or browser history.**
- **Investigation Over Auto-Blocking:** Every alert is accompanied by a transparent breakdown of observed facts vs. rule inferences. Playbook containment requires supervisor authorization.
- **Data Integrity:** Live endpoint events, imported CSV files, and simulated replay events carry distinct, tamper-evident badges (`[LIVE AGENT]`, `[IMPORTED]`, `[SIMULATED]`).

---

## 2. Central Server Setup on Windows

### Prerequisites
- **Node.js v20+** (Node.js v22+ recommended for native `node:sqlite`)
- **Windows 10/11 or Windows Server**
- PowerShell 5.1+ or PowerShell 7+

### Quick Start
1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd C:\Users\sivas\.gemini\antigravity\scratch\labtrace-soc
   ```
2. Start the server (binds to `0.0.0.0:3000` on all network interfaces):
   ```powershell
   node server.js
   ```
   *Custom configuration via environment variables:*
   ```powershell
   $env:PORT = "3000"
   $env:HOST = "0.0.0.0"
   $env:LABTRACE_API_KEY = "labtrace-secret-key"
   node server.js
   ```

### Access Points
- **Local Dashboard:** [http://localhost:3000/](http://localhost:3000/)
- **Health & Discovered LAN IPs:** `GET http://localhost:3000/api/health`
- **Real-Time SSE Stream:** `GET http://localhost:3000/api/stream`
- **Ingestion API:** `POST http://localhost:3000/api/ingest`
- **Audit Ledger Verification:** `GET http://localhost:3000/api/audit/verify`

---

## 3. LAN Access & Windows Firewall Configuration

### Finding Your Server's Private IPv4 Address
On startup, the server automatically inspects all active network adapters and displays reachable addresses. You can also view them with PowerShell:
```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.254' } | Select-Object InterfaceAlias, IPAddress
```
*Example:*
```text
InterfaceAlias IPAddress
-------------- ---------
Wi-Fi          172.16.97.104
Ethernet 2     192.168.56.1
```
*Lab devices on the same Wi-Fi will send events to `http://172.16.97.104:3000/api/ingest`.*

### Windows Firewall Configuration (Private Lab Network Only)
Run PowerShell as **Administrator** on the central server laptop to permit inbound connections on port 3000:

```powershell
# Create an inbound rule restricted strictly to the Private profile:
New-NetFirewallRule -DisplayName "LabTrace SOC Server (Port 3000)" `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 3000 `
                    -Profile Private `
                    -Action Allow
```

> [!WARNING]
> Never open port 3000 on Public networks. Always restrict the firewall rule to `-Profile Private`.

To remove the firewall rule when your lab session concludes:
```powershell
Remove-NetFirewallRule -DisplayName "LabTrace SOC Server (Port 3000)"
```

---

## 4. Authorized Endpoint Event Collection

LabTrace provides lightweight, opt-in collectors for devices you own or are explicitly authorized to monitor.

### Windows Security Event Collector (`collectors/windows-collector.ps1`)
Monitors the Windows Security Event log for logon metadata:
- **Event ID 4624:** Successful Logon
- **Event ID 4625:** Failed Logon

#### Step 1: Open PowerShell as Administrator on the target device
Reading the Windows Security log requires Administrator privileges or membership in the `Event Log Readers` local security group.

#### Step 2: Run the Collector
```powershell
cd collectors
.\windows-collector.ps1 -ServerUrl "http://YOUR_SERVER_IP:3000/api/ingest" `
                        -ApiKey "labtrace-secret-key" `
                        -PollIntervalSeconds 5 `
                        -Mode Live
```

#### Collector Features:
1. **Explicit Consent Verification:** Interactive prompt demands authorization confirmation before reading logs. Suppress with `-AcceptConsent` in scripted lab setups.
2. **Local Buffer & Auto-Retry:** If Wi-Fi disconnects, events buffer locally in `.labtrace-buffer.json` and automatically flush upon reconnection.
3. **Deterministic Deduplication:** Generates unique event hashes (`WIN-<Host>-<RecordId>-<Ticks>`) to prevent duplicate records upon retry.
4. **Local Noise Reduction:** Drops machine account events (`*$`) and internal system service logons before transmission.

### Cross-Platform Python Agent (`collectors/agent.py`)
For testing, Linux, or macOS lab devices:
```bash
python collectors/agent.py --server http://YOUR_SERVER_IP:3000/api/ingest --api-key labtrace-secret-key --consent
```

---

## 5. Live SOC Command Center

The **Live SOC Stream** page (`page-live`) provides full real-time operational oversight and supervised incident response:

### Operational Widgets & Visualizations
- **SOC KPI Strip:** Real-time counters for *Events Ingested*, *Open Incidents*, *Contained Targets*, *Logins Blocked*, *Accounts Locked*, and *PCs Isolated*.
- **Threat Level Gauge:** Semicircle SVG dial (0–100 score) with color transitions (`LOW`, `GUARDED`, `ELEVATED`, `CRITICAL`).
- **Events / Tick Sparkline:** Dynamic rolling SVG sparkline updating with every ingestion cycle.
- **Lab Floor PC Heatmap:** 12-workstation interactive grid (`PC-01` through `PC-12`) reflecting health (`clean`, `warn`, `crit` with red pulse, or `iso` with lock badge).
- **MITRE ATT&CK Matrix:** Technique badges (`T1110.001`, `T1110.003`, `T1078`, `T1021`, `T1078.002`, `T1550`) that highlight when detection rules fire.
- **Kill-Chain Progression:** 6-stage lifecycle bar (*Recon → Initial Access → Credential Access → Lateral Movement → Persistence → Impact*).
- **Attack Simulation Strip:** Quick buttons to inject controlled attack patterns for live demos:
  - ⚡ **Brute Force:** 5 failures followed by immediate success.
  - 🌊 **Password Spray:** Rapid attempts against multiple accounts on the same workstation.
  - 🌙 **Off-Hours Login:** Authentication outside standard operating hours.
  - 🔀 **Lateral Movement:** Cross-workstation authentication attempts.
  - 🍯 **Honeytoken Trip:** Access attempt against decoy accounts.
- **SOC Timeline:** Monospace response log recording all incident detections, alerts, and containment actions with UTC timestamps.

### Playbook Incident Actions
Every incident card in the queue includes dedicated action buttons:
| Action | Description | Authorization Requirement |
|---|---|---|
| **🔒 Lock** | Flags target account as compromised and increments blocked login metrics | Requires supervisor password + justification note |
| **🔌 Isolate** | Flags workstation for network containment and updates lab heatmap | Requires supervisor password + justification note |
| **🔄 Reset** | Clears containment status and triggers password reset workflow | Requires justification note |
| **⬆ Escalate** | Elevates incident priority and logs dispatch to Tier-2 SOC team | Requires justification note |

---

## 6. Defense Lab — Advanced Controls

The **Defense Lab** page (`page-cyber`) provides deep investigative features and security toggles:

### 1. Defense Feature Toggles
- 🤖 **Auto-Containment:** When toggled ON, Priority 1 (P1) incidents automatically execute supervisor-approved Lock and Isolate playbook actions.
- 🍯 **Honeytoken Decoy Accounts:** Monitors decoy accounts (`admin_backup`, `svc_old`). Any access triggers an immediate P1 alert, timeline entry, and toast notification.
- 🌐 **Threat-Intel Enrichment:** Toggles enriched GeoIP and reputation tags across events.
- ⏱ **Real SOC SLA Timers:** Displays real-time `SLA mm:ss` counters on incident cards, with flashing breach warnings when unresolved for >15 minutes.

### 2. Risk Score Analysis — Animated Motion Bar Chart
- Animated chart powered by `requestAnimationFrame` and CSS cubic-bezier transitions (`width 1s cubic-bezier(0.25, 0.8, 0.25, 1)`).
- Dynamically aggregates risk points and affected case counts across rules **R1–R6**.
- Transparently breaks down each rule's point contribution and plain-language explanation:
  - **R1: Failure Burst** (+3 pts) — Rapid failed logins then success within time window.
  - **R2: After-Hours** (+4 pts) — Authentication outside authorized lab operating hours.
  - **R3: Slow Guessing** (+2 pts) — Spread-out failures over 24h before success.
  - **R4: Persistent Fail** (+2 pts) — Repeated failures with no success recorded.
  - **R5: Cross-PC** (+3 pts) — Same account attempting auth across multiple workstations.
  - **R6: Password Spray** (+3 pts) — Multiple accounts targeted on the same workstation.

### 3. Account Risk Leaderboard (UEBA)
- Ranks top accounts by total authentication failures and composite risk scores.
- Highlights decoy honeytoken accounts with special indicators.

### 4. Shift Handover Report Generator
- Click **"📊 Generate Live Report"** to compile real data from the database and event buffer into a downloadable `.txt` report.
- Includes executive summary counts, ASCII rule distribution graphs, priority case details, logged playbook actions, and cryptographic audit ledger verification.

---

## 7. Detection Engine Rules (R1–R6)

| Rule ID | Rule Name | Detection Criteria | Explainability & Justification |
|---|---|---|---|
| **R1** | Failure Burst then Success | $\ge 3$ failures within 5 minutes followed by success | Distinguishes dictionary/brute-force attacks that succeeded from routine mistypes. |
| **R2** | After-Hours Access | Success outside lab schedule (08:30–17:30 or weekends) | Highlights access during unmonitored or off-hours lab periods. |
| **R3** | Slow Guessing then Success | $\ge 4$ failures spread across 24h before success | Detects low-and-slow credential guessing designed to evade burst rate limits. |
| **R4** | Ongoing Failures, No Access | Repeated failures with zero successful logins | Flags active credential stuffing or password testing in progress. |
| **R5** | Cross-Computer Failures | Failures across multiple workstations before success | Identifies lateral movement attempts within the lab environment. |
| **R6** | Password Spraying | $\ge 3$ distinct accounts failing on a single workstation | Detects horizontal password spray attempts against lab identities. |

---

## 8. Cryptographic Audit Ledger

Every analyst review decision, status update, and playbook containment action is recorded in a tamper-evident audit ledger chained using **SHA-256 hashes**:

$$\text{Block Hash} = \text{SHA-256}(\text{Seq} \parallel \text{Timestamp} \parallel \text{Reviewer} \parallel \text{Role} \parallel \text{Action} \parallel \text{Decision} \parallel \text{PrevHash})$$

- View entries in the **Audit Ledger** screen (`page-audit`).
- Click **"🔒 Verify Chain Integrity"** to validate the entire block chain mathematically from the genesis block.
- Verification API: `GET /api/audit/verify` returns full cryptographic validity and head block hash.

---

## 8. Windows Mobile Hotspot & Connected Network Devices Monitoring

When acting as a central SOC server for devices connected to your laptop's Wi-Fi hotspot, LabTrace SOC delivers **truthful discovery, explicit consent management, and observable network metadata**.

```
[ Friend's Phone or Laptop ]
      │
      ▼ (Wi-Fi Hotspot Connection)
┌────────────────────────────────────────────────────────┐
│ Windows Mobile Hotspot Adapter (Local Area Conn* 2)     │
│ Gateway IP: 192.168.137.1/24 (DHCP: 192.168.137.x)     │
└────────────────────────────────────────────────────────┘
      │
      ├─► [1] Kernel ARP Neighbor Discovery (arp -a, <100ms)
      │       Truthful IP, MAC OUI Vendor, & Hostname Resolution
      │
      ├─► [2] Consent Gate (ENG-02 Privacy Compliance)
      │       Unapproved devices: Flow logging suppressed
      │       Approved devices: Observable metadata captured
      │
      └─► [3] Optional Endpoint Agent (collectors/hotspot-agent.py/.ps1)
              Voluntary push of outbound connection metadata
```

### 8.1 Setup Steps for Host Server Laptop

1. **Enable Windows Mobile Hotspot**:
   - Open **Settings** -> **Network & internet** -> **Mobile hotspot**.
   - Toggle **Mobile hotspot** to **ON**.
   - Share connection over **Wi-Fi** (Band: Any or 2.4/5 GHz).
   - Windows assigns gateway IP `192.168.137.1` to the virtual adapter (`Local Area Connection* 2`).

2. **Configure Windows Firewall**:
   Run PowerShell as **Administrator** on the host server laptop:
   ```powershell
   New-NetFirewallRule -DisplayName "LabTrace SOC Hotspot Server (3000)" `
     -Direction Inbound `
     -LocalPort 3000 `
     -Protocol TCP `
     -Action Allow `
     -Profile Private
   ```

3. **Start the LabTrace SOC Server**:
   ```powershell
   node server.js
   ```
   The server listens on `0.0.0.0:3000`, making it directly reachable to hotspot clients at `http://192.168.137.1:3000/`.

4. **Open the Network Devices Dashboard**:
   - Navigate to [http://localhost:3000/](http://localhost:3000/) on your laptop.
   - Click **📶 Network Devices** in the sidebar.
   - View the live **Capability Detection Banner** (verifies Hotspot status, Npcap driver, and supported interfaces).

---

### 8.2 Truthful Capability Detection & Privacy Boundaries

LabTrace SOC **never invents device identities or fabricates packet captures**:
- **Supported Collection Methods**:
  - `Windows Kernel Neighbor Discovery`: Parses native kernel ARP tables (`arp -a` / `Get-NetNeighbor`) to detect real hotspot clients in <100ms.
  - `Hostname Resolution`: Performs non-blocking reverse lookups via NetBIOS / `mshome.net` / LLMNR.
  - `Vendor Identification`: Maps MAC OUI prefixes to hardware manufacturers (Apple, Intel, Samsung, HP, Dell, OnePlus, etc.).
  - `Authorized Endpoint Agent`: Clearly disclosed client agent voluntarily reports outbound socket flows.
  - `Host-Bound Socket Telemetry`: Observable TCP connections terminating at server port 3000.
- **Strict Privacy Boundaries**:
  - **No Packet Fabrication:** If transit packet inspection is unavailable without a WinPcap-mode driver, the dashboard truthfully indicates this limitation.
  - **No TLS/HTTPS Decryption:** Encrypted payload contents are strictly outside the defensive monitoring scope.
  - **No Surveillance:** Passwords, keystrokes, personal messages, and browser contents are never monitored.

---

### 8.3 Consent Workflow & Privacy Gate

Under policy **ENG-02**, connecting to Wi-Fi never implies consent to monitor:
1. **Consent Pending**: Discovered devices appear with a yellow `⏳ Consent Pending` badge. Granular network flow logging is strictly suppressed.
2. **Approved**: Clicking **Approve** (or running the agent with explicit agreement) transitions the device to `✅ Approved`. Observable network metadata is logged.
3. **Withdrawal**: Clicking **Withdraw** (or running `hotspot-agent.py --withdraw`) immediately revokes monitoring, suppresses flows, and records an unalterable SHA-256 audit entry.

---

### 8.4 Connecting an Authorized Device (Friend's Device)

When your friend connects their phone or laptop to your Wi-Fi hotspot:
1. Their device immediately appears in the **Connected Devices Table** with its local IP (`192.168.137.x`), MAC address, and vendor.
2. *(Optional)* For detailed endpoint telemetry, your friend can run the lightweight agent:

**On Linux / macOS / Android (Termux) / Windows (Python 3):**
```bash
python collectors/hotspot-agent.py --server http://192.168.137.1:3000
```
*Non-interactive mode with explicit agreement:*
```bash
python collectors/hotspot-agent.py --server http://192.168.137.1:3000 --consent
```

**On Windows (PowerShell):**
```powershell
.\collectors\hotspot-agent.ps1 -ServerUrl http://192.168.137.1:3000 -Consent
```

**Withdrawing Consent at Any Time:**
```bash
python collectors/hotspot-agent.py --server http://192.168.137.1:3000 --withdraw
```

---

### 8.5 Observable Network Detection Rules

| Rule ID | Rule Name | Condition | Severity |
|---|---|---|---|
| **NET-01** | Rapid Connection Burst | >15 connections in 15 seconds | `Review` |
| **NET-02** | Suspected Port Scan | Probed ≥5 distinct ports within 15 seconds | `Priority Review` |
| **NET-03** | Sensitive Port Probe | Probed administrative port (21 FTP, 22 SSH, 23 Telnet, 445 SMB, 3389 RDP) | `Priority Review` |
| **NET-04** | High Bandwidth Spike | Transferred >20 MB in a single observed flow | `Review` |

---

## 9. Automated Testing & Verification

Run the comprehensive automated test suite (19/19 passing tests):
```powershell
npm test
```

### Verified Test Cases:
1. `PASS`: LAN IPv4 interface discovery discovers active host network.
2. `PASS`: Server health endpoint returns healthy status and metadata.
3. `PASS`: Ingestion API rejects requests without API key (401).
4. `PASS`: Ingestion API rejects invalid API key (401).
5. `PASS`: Ingestion API rejects empty payload (400).
6. `PASS`: Ingestion API accepts valid event with master key.
7. `PASS`: Ingestion API rejects duplicate `event_id` without re-inserting.
8. `PASS`: Ingestion filters machine accounts (`*$`) without dropping valid users.
9. `PASS`: Enrollment API registers new authorized lab agent.
10. `PASS`: Agents API lists enrolled devices with calculated reporting state.
11. `PASS`: Demo login endpoint issues valid supervisor session in safe mode.
12. `PASS`: Cryptographic audit log records decisions and verifies SHA-256 chain integrity.
13. `PASS`: Replay API initializes sample stream with simulation tagging.
14. `PASS`: Network capability API reports truthful Windows networking and packet driver status.
15. `PASS`: Network devices API lists discovered hotspot devices without inventing data.
16. `PASS`: Hotspot agent enrollment requires explicit consent confirmation.
17. `PASS`: Hotspot agent ingestion accepts valid telemetry with agent token and rejects unauthenticated (401).
18. `PASS`: Consent management allows approving and withdrawing monitoring with audit logging.
19. `PASS`: Network simulation triggers explainable detection rules (NET-01 & NET-02) tagged as simulated.

---

## 10. Credentials & Default Ports

| Item | Value |
|---|---|
| **Port** | `3000` (Default, configurable via `PORT`) |
| **Host** | `0.0.0.0` (All interfaces, configurable via `HOST`) |
| **Master API Key** | `labtrace-secret-key` |
| **Supervisor Username** | `supervisor` |
| **Supervisor Password** | `labtrace-admin-2024` |
| **Quick Demo Access** | Click "Safe Demo Access" on the login screen |

---

## 11. Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| **Port 3000 in use** | A previous Node process is running | Run `Get-NetTCPConnection -LocalPort 3000 \| ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }` |
| **401 Unauthorized on Ingest** | Missing or invalid API key | Include header `x-api-key: labtrace-secret-key` or agent key |
| **429 Rate Limit Exceeded** | Sent >120 requests in 1 minute | Ingestion rate limiter active; batch events or increase collector interval |
| **Remote device cannot connect** | Windows Firewall blocking port | Add Private profile firewall rule as shown in Section 3 |
| **Collector requires Admin** | Windows Security log permission | Right-click PowerShell -> "Run as Administrator" |
| **Agent shows "NOT REPORTING"** | Agent heartbeats stopped (>10 min) | Ensure collector is running and network route to laptop is reachable |

---

## 12. License & Ethics

LabTrace SOC is designed strictly for **authorized educational cybersecurity labs and authorized defensive monitoring**. 
It strictly adheres to ENG-02 boundaries:
- Transparent evidence over black-box accusations.
- No surveillance of private user data (passwords, browsing, messages).
- Human analyst verification required for all containment decisions.
