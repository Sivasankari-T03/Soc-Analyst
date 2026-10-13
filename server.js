import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dbService } from './server/db.js';
import { analyzeNoise } from './server/noise.js';
import { enrichIp } from './server/enrichment.js';
import { auditService } from './server/audit.js';
import { playbooks } from './server/playbooks.js';
import { authService } from './server/auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.LABTRACE_API_KEY || 'labtrace-secret-key';

// In-memory ring buffer for low latency SSE feeds
const buffer = [];
const MAX_BUFFER = 50000;

// Connected SSE clients
const sseClients = new Set();

// Pre-fill buffer from database on startup
try {
  const existing = dbService.getRecentEvents(2000);
  buffer.push(...existing);
  console.log(`[Startup] Loaded ${existing.length} recent events from SQLite database into ring buffer.`);
} catch (err) {
  console.warn(`[Startup] DB initialization note: ${err.message}`);
}

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Heartbeat ping interval to keep SSE streams alive
setInterval(() => {
  for (const client of sseClients) {
    try {
      client.write(': ping\n\n');
    } catch (_) {
      sseClients.delete(client);
    }
  }
}, 25000);

// Background pruning job: cleans events older than 24h once per hour
setInterval(() => {
  try {
    const deleted = dbService.pruneOldEvents(24);
    if (deleted && deleted.changes > 0) {
      console.log(`[Retention] Pruned ${deleted.changes} events older than 24 hours.`);
    }
  } catch (err) {
    console.error(`[Retention Error] ${err.message}`);
  }
}, 60 * 60 * 1000);

// Helper: parse date to epoch ms
function parseEpoch(raw) {
  if (!raw) return Date.now();
  if (typeof raw === 'number') return raw;
  const parsed = Date.parse(raw);
  if (!isNaN(parsed)) return parsed;

  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/.exec(String(raw));
  if (m) {
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  return Date.now();
}

/* =========================================================================
   CORE EVENT PROCESSOR & SSE BROADCASTER
   ========================================================================= */
export async function processAndBroadcastEvents(rawEvents) {
  const processedEvents = [];
  let droppedNoise = 0;

  for (const item of rawEvents) {
    if (!item || !item.account) continue;

    // Noise Analysis: Filter machine accounts ($) and system accounts
    const noise = analyzeNoise(item);
    if (noise.drop) {
      droppedNoise++;
      continue;
    }

    const tsEpoch = parseEpoch(item.timestamp || item.ts);
    const tsFormatted = new Date(tsEpoch).toISOString().replace('T', ' ').slice(0, 19);

    // IP Enrichment: GeoIP and Threat Intelligence
    const enrichment = await enrichIp(item.ip);

    const eventRecord = {
      event_id: String(item.event_id || `EV-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`),
      timestamp: tsFormatted,
      ts: tsEpoch,
      account: noise.normalizedAccount,
      computer: String(item.computer || item.workstation || 'PC-01').trim(),
      ip: enrichment.ip,
      event: (String(item.event || '').toUpperCase() === 'FAILED' || item.event_id === '4625' || item.Id === 4625) ? 'FAILED' : 'SUCCESS',
      logon_type: noise.logonTypeLabel,
      department_case: item.department_case || (item.department ? String(item.department) : 'LIVE'),
      is_noise: noise.isNoise ? 1 : 0,
      enriched_geo: enrichment.geo,
      enriched_threat: enrichment.reputation
    };

    // Store in SQLite DB
    try {
      dbService.insertEvent(eventRecord);
    } catch (err) {
      console.warn(`[DB Insert Warning] ${err.message}`);
    }

    processedEvents.push(eventRecord);
  }

  // Push to memory ring buffer (capped at MAX_BUFFER)
  if (processedEvents.length > 0) {
    buffer.push(...processedEvents);
    if (buffer.length > MAX_BUFFER) {
      buffer.splice(0, buffer.length - MAX_BUFFER);
    }

    // Broadcast in real-time to all connected browser SSE clients
    const ssePayload = `data: ${JSON.stringify(processedEvents)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(ssePayload);
      } catch (_) {
        sseClients.delete(client);
      }
    }
  }

  return { accepted: processedEvents.length, droppedNoise, processedEvents };
}

/* =========================================================================
   BUILT-IN AUTOMATIC LIVE TRAFFIC FEEDER
   Allows the Live Feed to actively run out of the box when enabled!
   ========================================================================= */
let isFeederActive = true;
let feederTimer = null;

const DEMO_USERS = ['a.kumar', 'r.priya', 'm.arun', 's.divya', 'k.vikram', 't.nisha', 'guest_lab', 'svc.backup', 'admin.lab'];
const DEMO_PCS = ['PC-01', 'PC-02', 'PC-03', 'PC-04', 'PC-05', 'PC-06', 'PC-07', 'PC-08', 'PC-10', 'PC-11', 'PC-12'];
const EXTERNAL_IPS = [
  '185.220.101.4', // Known Tor Exit Node (DE)
  '45.155.205.9',  // Known GreyNoise Scanner (NL)
  '194.26.29.112', // Known Brute Force IP (RU)
  '141.98.11.11',  // Scanner (US)
  '203.0.113.42'   // External host
];

function randomInternalIp() {
  return `10.20.${1 + Math.floor(Math.random() * 8)}.${10 + Math.floor(Math.random() * 200)}`;
}

let feedCounter = Date.now();

function startFeeder() {
  if (feederTimer) clearInterval(feederTimer);
  isFeederActive = true;
  console.log('[Feeder] Automatic live traffic generator STARTED.');

  feederTimer = setInterval(async () => {
    try {
      const rand = Math.random();
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);

      if (rand < 0.12) {
        // Scenario 1: Occasional Brute Force Burst against a target PC
        const target = Math.random() < 0.5 ? 'guest_lab' : 'admin.lab';
        const pc = DEMO_PCS[Math.floor(Math.random() * DEMO_PCS.length)];
        const ip = EXTERNAL_IPS[Math.floor(Math.random() * EXTERNAL_IPS.length)];
        const burst = [];
        for (let i = 0; i < 3; i++) {
          feedCounter++;
          burst.push({
            event_id: `EV-BURST-${feedCounter}-${i}`,
            timestamp: now,
            account: target,
            computer: pc,
            ip,
            event: 'FAILED',
            logon_type: '10'
          });
        }
        feedCounter++;
        burst.push({
          event_id: `EV-BURST-${feedCounter}-ok`,
          timestamp: now,
          account: target,
          computer: pc,
          ip,
          event: 'SUCCESS',
          logon_type: '10'
        });
        await processAndBroadcastEvents(burst);

      } else if (rand < 0.20) {
        // Scenario 2: Password Spray on a lab PC
        const pc = 'PC-12';
        const ip = EXTERNAL_IPS[1];
        const spray = ['stu.01', 'stu.02', 'stu.03'].map((u, i) => {
          feedCounter++;
          return {
            event_id: `EV-SPRAY-${feedCounter}-${i}`,
            timestamp: now,
            account: u,
            computer: pc,
            ip,
            event: 'FAILED',
            logon_type: '2'
          };
        });
        await processAndBroadcastEvents(spray);

      } else {
        // Scenario 3: Standard routine campus activity
        feedCounter++;
        const user = DEMO_USERS[Math.floor(Math.random() * DEMO_USERS.length)];
        const pc = DEMO_PCS[Math.floor(Math.random() * DEMO_PCS.length)];
        const ip = randomInternalIp();
        const isFail = Math.random() < 0.14;

        await processAndBroadcastEvents([{
          event_id: `EV-LIVE-${feedCounter}`,
          timestamp: now,
          account: user,
          computer: pc,
          ip,
          event: isFail ? 'FAILED' : 'SUCCESS',
          logon_type: '2'
        }]);
      }
    } catch (err) {
      console.warn(`[Feeder Error] ${err.message}`);
    }
  }, 2200);
}

function stopFeeder() {
  if (feederTimer) {
    clearInterval(feederTimer);
    feederTimer = null;
  }
  isFeederActive = false;
  console.log('[Feeder] Automatic live traffic generator STOPPED.');
}

// Start feeder on boot so live stream is immediately active
startFeeder();

/* =========================================================================
   1. INGEST API (Windows PowerShell, Linux Collector, External Tools)
   ========================================================================= */
async function handleIngest(req, res) {
  const reqKey = req.headers['x-api-key'] || req.headers['authorization'];
  if (reqKey && reqKey !== API_KEY && reqKey !== `Bearer ${API_KEY}`) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  const rawEvents = [].concat(req.body || []);
  if (!rawEvents.length) {
    return res.status(400).json({ error: 'No events provided in request body' });
  }

  const result = await processAndBroadcastEvents(rawEvents);

  return res.status(200).json({
    status: 'ok',
    accepted: result.accepted,
    droppedNoise: result.droppedNoise,
    activeSseClients: sseClients.size
  });
}

app.post('/api/ingest', handleIngest);
app.post('/ingest', handleIngest);

/* =========================================================================
   2. SSE LIVE FEED STREAM
   ========================================================================= */
function handleStream(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  // Send backfill (last 2000 events)
  const backfill = buffer.slice(-2000);
  res.write(`data: ${JSON.stringify(backfill)}\n\n`);

  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
  });
}

app.get('/api/stream', handleStream);
app.get('/stream', handleStream);

/* =========================================================================
   3. FEEDER TOGGLE API (Controls Background Generator)
   ========================================================================= */
app.get('/api/feed/status', (req, res) => {
  res.json({ active: isFeederActive, connectedClients: sseClients.size });
});

app.post('/api/feed/start', (req, res) => {
  startFeeder();
  res.json({ success: true, active: true });
});

app.post('/api/feed/stop', (req, res) => {
  stopFeeder();
  res.json({ success: true, active: false });
});

/* =========================================================================
   4. CRYPTOGRAPHIC AUDIT LOG API (SHA-256 HASH CHAIN)
   ========================================================================= */
app.get('/api/audit', (req, res) => {
  const list = auditService.getAll();
  res.json(list);
});

app.get('/api/audit/verify', (req, res) => {
  const result = auditService.verifyChain();
  res.json(result);
});

app.post('/api/audit/decision', (req, res) => {
  const { reviewer, role, account, computer, rules, decision, note, event_ids } = req.body;
  if (!reviewer || !decision) {
    return res.status(400).json({ error: 'Reviewer and decision are required.' });
  }

  const entry = auditService.record({
    reviewer,
    role: role || 'Lab Assistant',
    action: 'REVIEW_DECISION',
    account,
    computer,
    rules,
    decision,
    note,
    event_ids
  });

  res.json({ success: true, entry });
});

/* =========================================================================
   5. PLAYBOOKS API (SUPERVISOR-APPROVED CONTAINMENT)
   ========================================================================= */
app.get('/api/playbook/status', (req, res) => {
  res.json(playbooks.getStatus());
});

app.post('/api/playbook/lock', async (req, res) => {
  try {
    const { account, reviewer, role, note, supervisorApproved } = req.body;
    const result = await playbooks.lock({ account, reviewer, role, note, supervisorApproved });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post(['/api/playbook/isolate', '/api/playbook/iso'], async (req, res) => {
  try {
    const { computer, reviewer, role, note, supervisorApproved } = req.body;
    const result = await playbooks.isolate({ computer, reviewer, role, note, supervisorApproved });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/playbook/reset', async (req, res) => {
  try {
    const { account, reviewer, role, note } = req.body;
    const result = await playbooks.reset({ account, reviewer, role, note });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post(['/api/playbook/escalate', '/api/playbook/esc'], async (req, res) => {
  try {
    const { incident, reviewer, role, note, channel } = req.body;
    const result = await playbooks.escalate({ incident, reviewer, role, note, channel });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/playbook/release', async (req, res) => {
  try {
    const { targetId, targetType, reviewer, role, note } = req.body;
    const result = await playbooks.release({ targetId, targetType, reviewer, role, note });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Always return JSON for unknown API routes instead of HTML error pages

/* =========================================================================
   6. AUTHENTICATION & SESSION MANAGEMENT API
   ========================================================================= */
app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const session = authService.login(username, password);
    res.json({ success: true, session });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post('/api/auth/sso', (req, res) => {
  const { provider, email, role } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required for SSO' });
  const session = authService.ssoLogin(provider || 'Entra ID', email, role);
  res.json({ success: true, session });
});

app.get('/api/auth/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '') || req.headers['x-session-token'];
  const session = authService.validateSession(token);
  if (!session) return res.status(401).json({ error: 'No active session' });
  res.json({ success: true, user: session });
});

app.post('/api/auth/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '') || req.headers['x-session-token'];
  authService.logout(token);
  res.json({ success: true });
});

/* =========================================================================
   7. SERVER STATUS API
   ========================================================================= */

app.get('/api/status', (req, res) => {
  res.json({
    app: 'LabTrace SOC Ingest Server',
    status: 'ONLINE',
    uptime: Math.round(process.uptime()),
    bufferEvents: buffer.length,
    activeSseClients: sseClients.size,
    feederActive: isFeederActive,
    containment: playbooks.getStatus(),
    auditChainLength: auditService.getAll().length
  });
});

// Add this block here, after all API routes
app.use('/api', (req, res) => {
  res.status(404).json({
    error: `API route not found: ${req.method} ${req.originalUrl}`
  });
});

app.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`🚀 LabTrace SOC Live Ingest Server running at: http://localhost:${PORT}`);
  console.log(`📡 SSE Event Feed available at:              http://localhost:${PORT}/api/stream`);
  console.log(`📥 Ingest Webhook available at:               POST http://localhost:${PORT}/api/ingest`);
  console.log(`⚡ Background Feeder:                          ACTIVE (events streaming)`);
  console.log(`🔐 Cryptographic Audit Log verification:       http://localhost:${PORT}/api/audit/verify`);
  console.log(`===============================================================\n`);
});
