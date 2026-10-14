import express from 'express';
import cors from 'cors';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dbService } from './server/db.js';
import { analyzeNoise } from './server/noise.js';
import { enrichIp } from './server/enrichment.js';
import { auditService } from './server/audit.js';
import { playbooks } from './server/playbooks.js';
import { authService } from './server/auth.js';
import { networkMonitor } from './server/network-monitor.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const HOST = process.env.HOST || '0.0.0.0';
const PORT = parseInt(process.env.PORT || '3000', 10);
const API_KEY = process.env.LABTRACE_API_KEY || 'labtrace-secret-key';

// Discover all non-internal IPv4 LAN addresses
export function getLanIpv4Addresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs || []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        addresses.push({
          interface: name,
          ip: addr.address,
          netmask: addr.netmask,
          cidr: addr.cidr
        });
      }
    }
  }
  return addresses;
}

// In-memory ring buffer for low latency SSE feeds
const buffer = [];
const MAX_BUFFER = 50000;

// Connected SSE clients
const sseClients = new Set();

// Connect Network Monitor broadcasts to SSE stream & SOC pipeline
networkMonitor.setBroadcastCallback((type, payload) => {
  const jsonPayload = JSON.stringify({ type, payload });
  for (const client of sseClients) {
    try {
      client.write(`event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`);
      client.write(`data: ${jsonPayload}\n\n`);
    } catch (_) {}
  }

  // If network event requires review, integrate into SOC ring buffer
  if (type === 'network_event' && payload && payload.severity && payload.severity !== 'Routine') {
    const socEv = {
      event_id: payload.event_id,
      ts: payload.ts || Date.now(),
      timestamp: payload.timestamp || new Date().toISOString(),
      account: payload.domain ? `net:${payload.domain}` : `port:${payload.dest_port || 'traffic'}`,
      computer: `HOTSPOT-${(payload.source_ip || 'client').replace(/\./g, '-')}`,
      event: 'FAILED',
      ip: payload.source_ip,
      logon_type: `NET-${payload.protocol || 'TCP'}`,
      department_case: payload.rule_id || 'HOTSPOT-ANOMALY',
      data_source: payload.data_source || 'live_hotspot',
      enriched_geo: { city: 'Hotspot Client', flag: '📶' },
      enriched_threat: { level: payload.severity === 'Priority Review' ? 'High' : 'Medium' }
    };
    buffer.push(socEv);
    if (buffer.length > MAX_BUFFER) buffer.shift();
  }
});

// Pre-fill buffer from database on startup
try {
  const existing = dbService.getRecentEvents(2000);
  buffer.push(...existing);
  console.log(`[Startup] Loaded ${existing.length} recent events from SQLite database into ring buffer.`);
} catch (err) {
  console.warn(`[Startup] DB initialization note: ${err.message}`);
}

app.use(cors());
// Limit request size to 2MB to prevent memory exhaustion
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting Map for Ingestion API
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQ = 120; // max 120 ingestion requests per minute per IP

function ingestRateLimiter(req, res, next) {
  const key = req.ip || req.headers['x-forwarded-for'] || 'default-client';
  const now = Date.now();
  let tracker = rateLimitMap.get(key);
  if (!tracker || now > tracker.resetTime) {
    tracker = { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };
    rateLimitMap.set(key, tracker);
  }
  tracker.count++;
  if (tracker.count > RATE_LIMIT_MAX_REQ) {
    return res.status(429).json({
      error: 'Rate limit exceeded for event ingestion. Maximum 120 requests/minute.',
      retryAfterSeconds: Math.ceil((tracker.resetTime - now) / 1000)
    });
  }
  next();
}

// Agent Authentication Helper
function authenticateAgent(req) {
  const rawKey = req.headers['x-api-key'] || req.headers['authorization'];
  if (!rawKey) {
    return { authenticated: false, reason: 'Missing API key header (x-api-key or Authorization: Bearer <key>)' };
  }
  const cleanKey = String(rawKey).replace(/^Bearer\s+/i, '').trim();

  // 1. Check against Master LabTrace API Key
  if (cleanKey === API_KEY) {
    return { authenticated: true, agent: { agent_id: 'MASTER-KEY', device_name: 'Master Lab Collector' } };
  }

  // 2. Check against enrolled agent credentials in DB
  const enrolled = dbService.getAgentByApiKey(cleanKey);
  if (enrolled && enrolled.status === 'active') {
    return { authenticated: true, agent: enrolled };
  }

  return { authenticated: false, reason: 'Invalid or revoked API key' };
}

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
export async function processAndBroadcastEvents(rawEvents, options = {}) {
  const processedEvents = [];
  let droppedNoise = 0;
  let duplicates = 0;
  let invalid = 0;

  const defaultSource = options.dataSource || 'live';
  const defaultAgentId = options.agentId || null;

  for (const item of rawEvents) {
    if (!item || typeof item !== 'object') {
      invalid++;
      continue;
    }

    if (!item.account || !item.computer) {
      // In Windows events, workstation may be WorkstationName or MachineName
      const comp = item.computer || item.workstation || item.WorkstationName || item.MachineName;
      if (!item.account || !comp) {
        invalid++;
        continue;
      }
      item.computer = comp;
    }

    // Noise Analysis: Filter machine accounts ($) and system accounts
    const noise = analyzeNoise(item);
    if (noise.drop) {
      droppedNoise++;
      continue;
    }

    const eventId = String(item.event_id || item.eventId || item.Id || `EV-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`);

    // Deduplication check: Avoid duplicate records
    if (dbService.hasEvent(eventId) || buffer.some(b => b.event_id === eventId)) {
      duplicates++;
      continue;
    }

    const tsEpoch = parseEpoch(item.timestamp || item.ts || item.TimeCreated);
    const tsFormatted = new Date(tsEpoch).toISOString().replace('T', ' ').slice(0, 19);

    // IP Enrichment: GeoIP and Threat Intelligence
    const enrichment = await enrichIp(item.ip || item.IpAddress);

    const isFailed = (
      String(item.event || '').toUpperCase() === 'FAILED' ||
      String(item.event_id || '') === '4625' ||
      item.Id === 4625 ||
      String(item.event || '').includes('4625')
    );

    const eventRecord = {
      event_id: eventId,
      timestamp: tsFormatted,
      ts: tsEpoch,
      account: noise.normalizedAccount,
      computer: String(item.computer || item.workstation || 'PC-01').trim(),
      ip: enrichment.ip,
      event: isFailed ? 'FAILED' : 'SUCCESS',
      logon_type: noise.logonTypeLabel,
      department_case: item.department_case || (item.department ? String(item.department) : (defaultSource === 'live' ? 'LIVE-SOC' : defaultSource.toUpperCase())),
      is_noise: noise.isNoise ? 1 : 0,
      enriched_geo: enrichment.geo,
      enriched_threat: enrichment.reputation,
      agent_id: item.agent_id || defaultAgentId,
      data_source: item.data_source || defaultSource
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

  return {
    accepted: processedEvents.length,
    duplicates,
    droppedNoise,
    invalid,
    processedEvents
  };
}

/* =========================================================================
   SIMULATED TRAFFIC FEEDER (OPT-IN, OFF BY DEFAULT)
   Does NOT run automatically to prevent mixing fake data with real events!
   ========================================================================= */
let isFeederActive = false;
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
  console.log('[Feeder] Simulation feeder explicitly STARTED.');

  feederTimer = setInterval(async () => {
    try {
      const rand = Math.random();
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);

      if (rand < 0.15) {
        // Brute Force Burst against target
        const target = Math.random() < 0.5 ? 'guest_lab' : 'admin.lab';
        const pc = DEMO_PCS[Math.floor(Math.random() * DEMO_PCS.length)];
        const ip = EXTERNAL_IPS[Math.floor(Math.random() * EXTERNAL_IPS.length)];
        const burst = [];
        for (let i = 0; i < 3; i++) {
          feedCounter++;
          burst.push({
            event_id: `EV-SIM-${feedCounter}-${i}`,
            timestamp: now,
            account: target,
            computer: pc,
            ip,
            event: 'FAILED',
            logon_type: '10',
            data_source: 'simulated'
          });
        }
        feedCounter++;
        burst.push({
          event_id: `EV-SIM-${feedCounter}-ok`,
          timestamp: now,
          account: target,
          computer: pc,
          ip,
          event: 'SUCCESS',
          logon_type: '10',
          data_source: 'simulated'
        });
        await processAndBroadcastEvents(burst, { dataSource: 'simulated' });

      } else {
        feedCounter++;
        const user = DEMO_USERS[Math.floor(Math.random() * DEMO_USERS.length)];
        const pc = DEMO_PCS[Math.floor(Math.random() * DEMO_PCS.length)];
        const ip = randomInternalIp();
        const isFail = Math.random() < 0.15;

        await processAndBroadcastEvents([{
          event_id: `EV-SIM-${feedCounter}`,
          timestamp: now,
          account: user,
          computer: pc,
          ip,
          event: isFail ? 'FAILED' : 'SUCCESS',
          logon_type: '2',
          data_source: 'simulated'
        }], { dataSource: 'simulated' });
      }
    } catch (err) {
      console.warn(`[Feeder Error] ${err.message}`);
    }
  }, 3000);
}

function stopFeeder() {
  if (feederTimer) {
    clearInterval(feederTimer);
    feederTimer = null;
  }
  isFeederActive = false;
  console.log('[Feeder] Simulation feeder STOPPED.');
}

/* =========================================================================
   1. SERVER HEALTH & STATUS ENDPOINTS
   ========================================================================= */
function getHealthPayload() {
  const lanAddresses = getLanIpv4Addresses();
  const dbStats = dbService.getEventStats();
  const enrolledAgents = dbService.listAgents();
  const now = Date.now();

  const agentsStatus = enrolledAgents.map(a => {
    const lastSeenEpoch = a.last_seen_at ? Date.parse(a.last_seen_at.replace(' ', 'T') + 'Z') : 0;
    const diffSec = (now - lastSeenEpoch) / 1000;
    let status = 'NOT REPORTING';
    if (diffSec < 60) status = 'ONLINE';
    else if (diffSec < 600) status = 'IDLE';

    return {
      agent_id: a.agent_id,
      device_name: a.device_name,
      hostname: a.hostname,
      ip: a.ip,
      status,
      last_seen: a.last_seen_at,
      events_count: a.events_count
    };
  });

  return {
    status: 'healthy',
    app: 'LabTrace SOC Central Server',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    host: HOST,
    port: PORT,
    lanAddresses,
    primaryLanUrl: lanAddresses[0] ? `http://${lanAddresses[0].ip}:${PORT}/` : `http://localhost:${PORT}/`,
    activeSseClients: sseClients.size,
    bufferEvents: buffer.length,
    feederActive: isFeederActive,
    agents: agentsStatus,
    activeAgentsCount: agentsStatus.filter(a => a.status === 'ONLINE').length,
    stats: dbStats,
    hotspot: networkMonitor.detectCapabilities(),
    networkStats: dbService.getNetworkStats()
  };
}

app.get(['/api/health', '/health'], (req, res) => {
  res.json(getHealthPayload());
});

app.get('/api/status', (req, res) => {
  res.json(getHealthPayload());
});

/* =========================================================================
   2. AUTHENTICATED AGENT INGESTION API
   ========================================================================= */
async function handleIngest(req, res) {
  const auth = authenticateAgent(req);
  if (!auth.authenticated) {
    return res.status(401).json({ error: 'Unauthorized: ' + auth.reason });
  }

  const rawEvents = [].concat(req.body || []);
  if (!rawEvents.length) {
    return res.status(400).json({ error: 'No events provided in request body' });
  }

  // Determine Agent Identity
  let agentId = req.headers['x-agent-id'] || auth.agent?.agent_id;
  const clientIp = req.ip || req.headers['x-forwarded-for'] || '127.0.0.1';

  // If this agent is enrolled, update heartbeat and stats
  if (agentId && agentId !== 'MASTER-KEY') {
    try {
      dbService.updateAgentHeartbeat(agentId, clientIp, rawEvents.length);
    } catch (_) {}
  }

  const result = await processAndBroadcastEvents(rawEvents, {
    dataSource: 'live',
    agentId: agentId || null
  });

  return res.status(200).json({
    status: 'ok',
    accepted: result.accepted,
    duplicates: result.duplicates,
    droppedNoise: result.droppedNoise,
    invalid: result.invalid,
    activeSseClients: sseClients.size
  });
}

app.post('/api/ingest', ingestRateLimiter, handleIngest);
app.post('/ingest', ingestRateLimiter, handleIngest);

/* =========================================================================
   3. AGENT ENROLLMENT & MANAGEMENT API
   ========================================================================= */
app.get('/api/agents', (req, res) => {
  const list = dbService.listAgents();
  const now = Date.now();
  const enhanced = list.map(a => {
    const lastSeenEpoch = a.last_seen_at ? Date.parse(a.last_seen_at.replace(' ', 'T') + 'Z') : 0;
    const diffSec = (now - lastSeenEpoch) / 1000;
    let reportingState = 'NOT REPORTING';
    if (diffSec < 60) reportingState = 'ONLINE';
    else if (diffSec < 600) reportingState = 'IDLE';

    return {
      ...a,
      reportingState,
      secondsSinceLastSeen: Math.round(diffSec)
    };
  });
  res.json({ agents: enhanced });
});

app.post('/api/agents/enroll', (req, res) => {
  const { device_name, hostname, ip, api_key, os_info } = req.body;
  if (!device_name && !hostname) {
    return res.status(400).json({ error: 'device_name or hostname is required' });
  }

  const agent_id = `AGENT-${(hostname || device_name).replace(/[^a-zA-Z0-9_-]/g, '').toUpperCase()}`;
  const generatedKey = api_key || `labtrace-agent-${Math.random().toString(36).slice(2, 10)}`;

  try {
    dbService.enrollAgent({
      agent_id,
      device_name: device_name || hostname,
      hostname: hostname || device_name,
      ip: ip || req.ip || '',
      api_key: generatedKey,
      os_info: os_info || 'Windows Security Endpoint'
    });

    res.json({
      success: true,
      agent_id,
      api_key: generatedKey,
      device_name: device_name || hostname,
      message: 'Agent enrolled successfully. Configure agent script with this API Key.'
    });
  } catch (err) {
    res.status(500).json({ error: `Enrollment error: ${err.message}` });
  }
});

app.post('/api/agents/:id/revoke', (req, res) => {
  const agentId = req.params.id;
  dbService.revokeAgent(agentId);
  res.json({ success: true, message: `Agent ${agentId} revoked.` });
});

/* =========================================================================
   4. SSE LIVE FEED STREAM
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
   5. REPLAY & DEMO MODE API (SEPARATE, EXPLICITLY LABELED)
   ========================================================================= */
let activeReplayTimer = null;

app.post('/api/replay/start', async (req, res) => {
  if (activeReplayTimer) {
    clearInterval(activeReplayTimer);
    activeReplayTimer = null;
  }

  // Load sample CSV
  const samplePath = path.join(__dirname, 'labtrace-sample.csv');
  if (!fs.existsSync(samplePath)) {
    return res.status(404).json({ error: 'Sample CSV file not found on server' });
  }

  try {
    const rawCsv = fs.readFileSync(samplePath, 'utf8');
    const lines = rawCsv.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('event_id'));
    const replayRows = lines.map((line, idx) => {
      const parts = line.split(',');
      return {
        event_id: `EV-REPLAY-${Date.now()}-${idx}`,
        timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
        account: parts[2] ? parts[2].trim() : 'guest_lab',
        computer: parts[3] ? parts[3].trim() : 'PC-01',
        event: parts[4] ? parts[4].trim().toUpperCase() : 'SUCCESS',
        department_case: 'REPLAY-DEMO',
        ip: parts[5] ? parts[5].trim() : '10.20.1.15',
        data_source: 'simulated'
      };
    });

    let index = 0;
    activeReplayTimer = setInterval(async () => {
      if (index >= replayRows.length) {
        clearInterval(activeReplayTimer);
        activeReplayTimer = null;
        console.log('[Replay] Completed streaming all sample records.');
        return;
      }

      const chunk = replayRows.slice(index, index + 3);
      index += 3;
      await processAndBroadcastEvents(chunk, { dataSource: 'simulated' });
    }, 1500);

    res.json({
      success: true,
      totalRows: replayRows.length,
      message: 'Replay demo streaming started. All events are tagged as [SIMULATED REPLAY DATA].'
    });
  } catch (err) {
    res.status(500).json({ error: `Replay failed: ${err.message}` });
  }
});

app.post('/api/replay/stop', (req, res) => {
  if (activeReplayTimer) {
    clearInterval(activeReplayTimer);
    activeReplayTimer = null;
  }
  res.json({ success: true, message: 'Replay stopped.' });
});

/* =========================================================================
   6. FEEDER TOGGLE API (Controls Optional Background Feeder)
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
   7. CRYPTOGRAPHIC AUDIT LOG API (SHA-256 HASH CHAIN)
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
   8. PLAYBOOKS API (SUPERVISOR-APPROVED CONTAINMENT & INVESTIGATION)
   ========================================================================= */
app.get('/api/playbook/status', (req, res) => {
  res.json(playbooks.getStatus());
});

app.post('/api/playbook/lock', async (req, res) => {
  try {
    const { account, reviewer, role, note, justification, supervisor, supervisorApproved } = req.body;
    const finalReviewer = reviewer || supervisor || 'Supervisor';
    const finalRole = role || (finalReviewer.toLowerCase().includes('analyst') ? 'Analyst' : 'Supervisor');
    const finalNote = note || justification || 'Supervisor authorized lock action';
    const isApproved = supervisorApproved !== undefined ? Boolean(supervisorApproved) : (finalRole === 'Supervisor');
    const result = await playbooks.lock({
      account,
      reviewer: finalReviewer,
      role: finalRole,
      note: finalNote,
      supervisorApproved: isApproved
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post(['/api/playbook/isolate', '/api/playbook/iso'], async (req, res) => {
  try {
    const { computer, reviewer, role, note, justification, supervisor, supervisorApproved } = req.body;
    const finalReviewer = reviewer || supervisor || 'Supervisor';
    const finalRole = role || (finalReviewer.toLowerCase().includes('analyst') ? 'Analyst' : 'Supervisor');
    const finalNote = note || justification || 'Supervisor authorized workstation isolation';
    const isApproved = supervisorApproved !== undefined ? Boolean(supervisorApproved) : (finalRole === 'Supervisor');
    const result = await playbooks.isolate({
      computer,
      reviewer: finalReviewer,
      role: finalRole,
      note: finalNote,
      supervisorApproved: isApproved
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/playbook/reset', async (req, res) => {
  try {
    const { account, reviewer, role, note, justification, supervisor } = req.body;
    const finalReviewer = reviewer || supervisor || 'Supervisor';
    const finalRole = role || 'Supervisor';
    const finalNote = note || justification || 'Password reset requested';
    const result = await playbooks.reset({
      account,
      reviewer: finalReviewer,
      role: finalRole,
      note: finalNote
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post(['/api/playbook/escalate', '/api/playbook/esc'], async (req, res) => {
  try {
    const { incident, reviewer, role, note, justification, channel, supervisor } = req.body;
    const finalReviewer = reviewer || supervisor || 'Supervisor';
    const finalRole = role || 'Supervisor';
    const finalNote = note || justification || 'Manual analyst escalation';
    const result = await playbooks.escalate({
      incident: incident || {},
      reviewer: finalReviewer,
      role: finalRole,
      note: finalNote,
      channel: channel || 'Tier-2 SOC Team'
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/playbook/release', async (req, res) => {
  try {
    const { targetId, targetType, reviewer, role, note, justification, supervisor } = req.body;
    const finalReviewer = reviewer || supervisor || 'Supervisor';
    const finalRole = role || 'Supervisor';
    const finalNote = note || justification || 'Containment released';
    const result = await playbooks.release({
      targetId,
      targetType,
      reviewer: finalReviewer,
      role: finalRole,
      note: finalNote
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* =========================================================================
   8B. NETWORK DEVICES & HOTSPOT MONITORING API
   ========================================================================= */
app.get('/api/network/status', (req, res) => {
  res.json(networkMonitor.detectCapabilities());
});

app.get('/api/network/devices', async (req, res) => {
  try {
    const shouldScan = req.query.scan !== 'false';
    if (shouldScan) {
      await networkMonitor.scanDevices();
    }
    const devices = dbService.listNetworkDevices();
    const capabilities = networkMonitor.detectCapabilities();
    res.json({
      success: true,
      capabilities,
      devices
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/network/devices/:id', (req, res) => {
  try {
    const device = dbService.getNetworkDevice(req.params.id);
    if (!device) return res.status(404).json({ error: `Device ${req.params.id} not found` });
    const events = dbService.getNetworkEvents({ deviceId: req.params.id, limit: 100 });
    res.json({ success: true, device, events });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/network/events', (req, res) => {
  try {
    const deviceId = req.query.deviceId || null;
    const limit = parseInt(req.query.limit || '100', 10);
    const events = dbService.getNetworkEvents({ deviceId, limit });
    res.json({ success: true, events });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/network/consent', (req, res) => {
  try {
    const { deviceId, status, notes, reviewer } = req.body;
    if (!deviceId || !status) {
      return res.status(400).json({ error: 'deviceId and status (Approved, Not Monitored, or Consent Pending) are required' });
    }
    const result = networkMonitor.setConsent(deviceId, status, notes, reviewer || 'Supervisor');
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/network/agent/enroll', (req, res) => {
  try {
    const { deviceId, ip, hostname, deviceType, consentGranted } = req.body;
    const clientIp = ip || req.headers['x-forwarded-for'] || req.ip || '192.168.137.2';
    if (!consentGranted) {
      return res.status(400).json({ error: 'Explicit consent confirmation is required for agent enrollment.' });
    }
    const result = networkMonitor.enrollAgent({ deviceId, ip: clientIp, hostname, deviceType });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/network/agent/events', (req, res) => {
  try {
    const apiKey = req.headers['x-agent-key'] || req.headers['x-api-key'] || req.query.apiKey;
    if (!apiKey) {
      return res.status(401).json({ error: 'Unauthorized: Missing agent authentication key' });
    }

    const events = [].concat(req.body || []);
    if (!events.length) {
      return res.status(400).json({ error: 'No network telemetry provided' });
    }

    const processed = [];
    for (const ev of events) {
      const resEvent = networkMonitor.ingestNetworkEvent({
        ...ev,
        data_source: 'live_agent'
      });
      processed.push(resEvent);
    }

    res.json({
      success: true,
      processed: processed.length,
      events: processed
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/network/test/simulate', (req, res) => {
  try {
    const { scenario = 'burst', sourceIp = '192.168.137.72', destIp = '192.168.137.1' } = req.body;
    const nowIso = new Date().toISOString();
    const simulatedEvents = [];

    if (scenario === 'burst') {
      for (let i = 0; i < 18; i++) {
        simulatedEvents.push({
          source_ip: sourceIp,
          dest_ip: destIp,
          dest_port: 8000 + i,
          protocol: 'TCP',
          bytes_transferred: 512,
          data_source: 'simulated',
          timestamp: nowIso
        });
      }
    } else if (scenario === 'port_scan') {
      [21, 22, 23, 80, 443, 445, 3389].forEach(p => {
        simulatedEvents.push({
          source_ip: sourceIp,
          dest_ip: destIp,
          dest_port: p,
          protocol: 'TCP',
          bytes_transferred: 128,
          data_source: 'simulated',
          timestamp: nowIso
        });
      });
    } else if (scenario === 'probe_sensitive') {
      simulatedEvents.push({
        source_ip: sourceIp,
        dest_ip: destIp,
        dest_port: 3389,
        protocol: 'TCP',
        bytes_transferred: 256,
        data_source: 'simulated',
        timestamp: nowIso
      });
    } else {
      simulatedEvents.push({
        source_ip: sourceIp,
        dest_ip: '1.1.1.1',
        dest_port: 443,
        protocol: 'TCP',
        domain: 'authorized-lab.org',
        bytes_transferred: 1024,
        data_source: 'simulated',
        timestamp: nowIso
      });
    }

    const processed = [];
    for (const ev of simulatedEvents) {
      processed.push(networkMonitor.ingestNetworkEvent(ev));
    }

    res.json({
      success: true,
      scenario,
      simulated: processed.length,
      message: `Simulated ${scenario} scenario injected and clearly marked [SIMULATED].`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================================================================
   9. AUTHENTICATION & DEMO LOGIN API
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

app.all(['/api/auth/demo', '/auth/demo'], (req, res) => {
  try {
    const session = authService.demoLogin();
    res.json({ success: true, session, message: 'Authenticated in safe Demo Mode.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/sso', (req, res) => {
  const { provider, email, role } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required for SSO' });
  const session = authService.ssoLogin(provider || 'Entra ID', email, role);
  res.json({ success: true, session });
});

app.get('/api/auth/me', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || req.headers['x-session-token'];
  const session = authService.validateSession(token);
  if (!session) return res.status(401).json({ error: 'No active session' });
  res.json({ success: true, user: session });
});

app.post('/api/auth/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || req.headers['x-session-token'];
  authService.logout(token);
  res.json({ success: true });
});

// JSON fallback for missing API endpoints
app.use('/api', (req, res) => {
  res.status(404).json({
    error: `API endpoint not found: ${req.method} ${req.originalUrl}`
  });
});

/* =========================================================================
   10. SERVER STARTUP & NETWORK BINDING
   ========================================================================= */
export const serverInstance = app.listen(PORT, HOST, () => {
  const lanAddresses = getLanIpv4Addresses();

  // Start periodic hotspot & network device scanner
  networkMonitor.startPeriodicScanning(8000);

  console.log(`\n====================================================================`);
  console.log(`🛡️  LabTrace SOC Central Ingest Server is ONLINE`);
  console.log(`====================================================================`);
  console.log(`🏠 Localhost:               http://localhost:${PORT}`);
  console.log(`🌐 Host Interface:          ${HOST}:${PORT}`);
  
  if (lanAddresses.length > 0) {
    console.log(`📡 Authorized LAN Access:`);
    lanAddresses.forEach(net => {
      console.log(`   * [${net.interface}] http://${net.ip}:${PORT}/`);
      console.log(`     Ingest API: http://${net.ip}:${PORT}/api/ingest`);
    });
  } else {
    console.log(`⚠️  No active LAN IPv4 interface detected (using localhost only).`);
  }

  console.log(`\n🔌 Endpoint Agent Ingest:    POST http://localhost:${PORT}/api/ingest`);
  console.log(`💓 Server Health Endpoint:   GET  http://localhost:${PORT}/api/health`);
  console.log(`📡 Real-Time SSE Stream:     GET  http://localhost:${PORT}/api/stream`);
  console.log(`🔐 Cryptographic Audit Log:  GET  http://localhost:${PORT}/api/audit/verify`);
  console.log(`🔒 Default Master API Key:   ${API_KEY}`);
  console.log(`====================================================================\n`);
});

export default app;
