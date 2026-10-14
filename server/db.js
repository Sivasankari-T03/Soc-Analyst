import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.resolve(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'labtrace.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode for high performance concurrent reads and writes
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA synchronous = NORMAL;');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    timestamp TEXT NOT NULL,
    ts_epoch INTEGER NOT NULL,
    account TEXT NOT NULL,
    computer TEXT NOT NULL,
    ip TEXT,
    event TEXT NOT NULL,
    logon_type TEXT,
    department_case TEXT,
    is_noise INTEGER DEFAULT 0,
    enriched_geo TEXT,
    enriched_threat TEXT,
    agent_id TEXT,
    data_source TEXT DEFAULT 'live',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(ts_epoch);
  CREATE INDEX IF NOT EXISTS idx_events_account ON events(account);
  CREATE INDEX IF NOT EXISTS idx_events_computer ON events(computer);
  CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(event_id);

  CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    hostname TEXT,
    ip TEXT,
    api_key TEXT NOT NULL UNIQUE,
    os_info TEXT,
    status TEXT DEFAULT 'active',
    enrolled_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT,
    events_count INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    account TEXT,
    computer TEXT,
    rules TEXT,
    decision TEXT,
    note TEXT,
    event_ids TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS containment (
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL PRIMARY KEY,
    action TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    reason TEXT,
    timestamp TEXT NOT NULL,
    active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS network_devices (
    device_id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    connection_status TEXT DEFAULT 'Connected',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    duration_seconds INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    device_type TEXT DEFAULT 'Unknown',
    monitoring_status TEXT DEFAULT 'Consent Pending',
    consent_timestamp TEXT,
    consent_notes TEXT,
    interface_alias TEXT,
    agent_enrolled INTEGER DEFAULT 0,
    api_key TEXT,
    last_activity TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_netdev_ip ON network_devices(ip);
  CREATE INDEX IF NOT EXISTS idx_netdev_mac ON network_devices(mac);
  CREATE INDEX IF NOT EXISTS idx_netdev_status ON network_devices(connection_status);

  CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    device_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ts_epoch INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    protocol TEXT DEFAULT 'TCP',
    domain TEXT,
    bytes_transferred INTEGER DEFAULT 0,
    event_type TEXT NOT NULL,
    severity TEXT DEFAULT 'Routine',
    rule_id TEXT,
    explanation TEXT,
    data_source TEXT DEFAULT 'live_hotspot',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_netev_epoch ON network_events(ts_epoch);
  CREATE INDEX IF NOT EXISTS idx_netev_device ON network_events(device_id);
  CREATE INDEX IF NOT EXISTS idx_netev_severity ON network_events(severity);
`);

// Safe column migrations in case existing table didn't have these columns
try { db.exec("ALTER TABLE events ADD COLUMN agent_id TEXT;"); } catch (_) {}
try { db.exec("ALTER TABLE events ADD COLUMN data_source TEXT DEFAULT 'live';"); } catch (_) {}

// Prepared statements for high throughput
const insertEventStmt = db.prepare(`
  INSERT OR IGNORE INTO events 
  (event_id, timestamp, ts_epoch, account, computer, ip, event, logon_type, department_case, is_noise, enriched_geo, enriched_threat, agent_id, data_source)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const checkEventExistsStmt = db.prepare(`
  SELECT 1 FROM events WHERE event_id = ? LIMIT 1
`);

const selectRecentStmt = db.prepare(`
  SELECT event_id, timestamp, ts_epoch as ts, account, computer, ip, event, logon_type, department_case, enriched_geo, enriched_threat, agent_id, data_source
  FROM events
  WHERE ts_epoch >= ?
  ORDER BY ts_epoch ASC
  LIMIT ?
`);

const selectAllRecentStmt = db.prepare(`
  SELECT event_id, timestamp, ts_epoch as ts, account, computer, ip, event, logon_type, department_case, enriched_geo, enriched_threat, agent_id, data_source
  FROM events
  ORDER BY ts_epoch DESC
  LIMIT ?
`);

const pruneEventsStmt = db.prepare(`
  DELETE FROM events WHERE ts_epoch < ?
`);

const getLatestAuditStmt = db.prepare(`
  SELECT * FROM audit_trail ORDER BY seq DESC LIMIT 1
`);

const insertAuditStmt = db.prepare(`
  INSERT INTO audit_trail
  (seq, timestamp, reviewer, role, action, account, computer, rules, decision, note, event_ids, prev_hash, hash)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const getAuditTrailStmt = db.prepare(`
  SELECT * FROM audit_trail ORDER BY seq ASC
`);

const upsertContainmentStmt = db.prepare(`
  INSERT INTO containment (target_type, target_id, action, initiated_by, reason, timestamp, active)
  VALUES (?, ?, ?, ?, ?, ?, 1)
  ON CONFLICT(target_id) DO UPDATE SET
    action = excluded.action,
    initiated_by = excluded.initiated_by,
    reason = excluded.reason,
    timestamp = excluded.timestamp,
    active = 1
`);

const deleteContainmentStmt = db.prepare(`
  DELETE FROM containment WHERE target_id = ?
`);

const getActiveContainmentStmt = db.prepare(`
  SELECT * FROM containment WHERE active = 1
`);

// Agent Statements
const enrollAgentStmt = db.prepare(`
  INSERT INTO agents (agent_id, device_name, hostname, ip, api_key, os_info, status, enrolled_at, last_seen_at, events_count)
  VALUES (?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
  ON CONFLICT(agent_id) DO UPDATE SET
    device_name = excluded.device_name,
    hostname = excluded.hostname,
    ip = excluded.ip,
    api_key = excluded.api_key,
    os_info = excluded.os_info,
    status = 'active'
`);

const getAgentByApiKeyStmt = db.prepare(`
  SELECT * FROM agents WHERE api_key = ? AND status = 'active' LIMIT 1
`);

const getAgentByIdStmt = db.prepare(`
  SELECT * FROM agents WHERE agent_id = ? LIMIT 1
`);

const listAgentsStmt = db.prepare(`
  SELECT agent_id, device_name, hostname, ip, status, enrolled_at, last_seen_at, events_count
  FROM agents
  ORDER BY last_seen_at DESC
`);

const updateAgentHeartbeatStmt = db.prepare(`
  UPDATE agents 
  SET last_seen_at = CURRENT_TIMESTAMP,
      ip = COALESCE(?, ip),
      events_count = events_count + ?
  WHERE agent_id = ?
`);

const revokeAgentStmt = db.prepare(`
  UPDATE agents SET status = 'revoked' WHERE agent_id = ?
`);

const countEventsStmt = db.prepare(`
  SELECT COUNT(*) as count FROM events
`);

const countEventsBySourceStmt = db.prepare(`
  SELECT data_source, COUNT(*) as count FROM events GROUP BY data_source
`);

const getLastEventTimestampStmt = db.prepare(`
  SELECT timestamp FROM events ORDER BY ts_epoch DESC LIMIT 1
`);

const upsertNetworkDeviceStmt = db.prepare(`
  INSERT INTO network_devices (
    device_id, ip, mac, hostname, connection_status, first_seen_at, last_seen_at,
    duration_seconds, bytes_sent, bytes_received, device_type, monitoring_status,
    consent_timestamp, consent_notes, interface_alias, agent_enrolled, api_key, last_activity
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(device_id) DO UPDATE SET
    ip = excluded.ip,
    mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE network_devices.mac END,
    hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE network_devices.hostname END,
    connection_status = excluded.connection_status,
    last_seen_at = excluded.last_seen_at,
    duration_seconds = MAX(excluded.duration_seconds, network_devices.duration_seconds),
    bytes_sent = network_devices.bytes_sent + excluded.bytes_sent,
    bytes_received = network_devices.bytes_received + excluded.bytes_received,
    device_type = CASE WHEN excluded.device_type != 'Unknown' THEN excluded.device_type ELSE network_devices.device_type END,
    interface_alias = CASE WHEN excluded.interface_alias != '' THEN excluded.interface_alias ELSE network_devices.interface_alias END,
    last_activity = COALESCE(excluded.last_activity, network_devices.last_activity)
`);

const getNetworkDeviceByIdStmt = db.prepare(`
  SELECT * FROM network_devices WHERE device_id = ?
`);

const getNetworkDeviceByIpStmt = db.prepare(`
  SELECT * FROM network_devices WHERE ip = ? LIMIT 1
`);

const listNetworkDevicesStmt = db.prepare(`
  SELECT * FROM network_devices ORDER BY 
    CASE connection_status WHEN 'Connected' THEN 1 WHEN 'Connected (Idle)' THEN 2 ELSE 3 END,
    last_seen_at DESC
`);

const updateDeviceConsentStmt = db.prepare(`
  UPDATE network_devices 
  SET monitoring_status = ?, consent_timestamp = ?, consent_notes = ?
  WHERE device_id = ?
`);

const updateDeviceTrafficStmt = db.prepare(`
  UPDATE network_devices
  SET bytes_sent = bytes_sent + ?,
      bytes_received = bytes_received + ?,
      last_activity = CURRENT_TIMESTAMP
  WHERE device_id = ?
`);

const markStaleDevicesStmt = db.prepare(`
  UPDATE network_devices
  SET connection_status = 'Disconnected'
  WHERE connection_status LIKE 'Connected%'
    AND last_seen_at < ?
`);

const insertNetworkEventStmt = db.prepare(`
  INSERT INTO network_events (
    event_id, device_id, timestamp, ts_epoch, source_ip, dest_ip, dest_port,
    protocol, domain, bytes_transferred, event_type, severity, rule_id, explanation, data_source
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const selectRecentNetworkEventsStmt = db.prepare(`
  SELECT * FROM network_events
  ORDER BY ts_epoch DESC
  LIMIT ?
`);

const selectDeviceNetworkEventsStmt = db.prepare(`
  SELECT * FROM network_events
  WHERE device_id = ?
  ORDER BY ts_epoch DESC
  LIMIT ?
`);

const countNetworkDevicesStmt = db.prepare(`
  SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN connection_status LIKE 'Connected%' THEN 1 ELSE 0 END) as connected,
    SUM(CASE WHEN monitoring_status = 'Approved' THEN 1 ELSE 0 END) as approved,
    SUM(CASE WHEN monitoring_status = 'Consent Pending' THEN 1 ELSE 0 END) as pending
  FROM network_devices
`);

export const dbService = {
  insertEvent(ev) {
    const geoStr = ev.enriched_geo ? JSON.stringify(ev.enriched_geo) : null;
    const threatStr = ev.enriched_threat ? JSON.stringify(ev.enriched_threat) : null;
    return insertEventStmt.run(
      ev.event_id,
      ev.timestamp,
      ev.ts,
      ev.account,
      ev.computer,
      ev.ip || '127.0.0.1',
      ev.event,
      ev.logon_type || '',
      ev.department_case || '',
      ev.is_noise ? 1 : 0,
      geoStr,
      threatStr,
      ev.agent_id || null,
      ev.data_source || 'live'
    );
  },

  hasEvent(eventId) {
    if (!eventId) return false;
    const row = checkEventExistsStmt.get(String(eventId));
    return Boolean(row);
  },

  getRecentEvents(limit = 2000, sinceEpoch = null) {
    let rows;
    if (sinceEpoch != null) {
      rows = selectRecentStmt.all(sinceEpoch, limit);
    } else {
      rows = selectAllRecentStmt.all(limit);
      rows.reverse(); // return in ascending order for engine
    }

    return rows.map(r => ({
      ...r,
      enriched_geo: r.enriched_geo ? JSON.parse(r.enriched_geo) : null,
      enriched_threat: r.enriched_threat ? JSON.parse(r.enriched_threat) : null
    }));
  },

  pruneOldEvents(hours = 24) {
    const cutoff = Date.now() - (hours * 3600 * 1000);
    return pruneEventsStmt.run(cutoff);
  },

  // Agents
  enrollAgent({ agent_id, device_name, hostname, ip, api_key, os_info, initial_events = 0 }) {
    return enrollAgentStmt.run(
      agent_id,
      device_name || agent_id,
      hostname || '',
      ip || '',
      api_key,
      os_info || 'Windows Security Endpoint',
      initial_events
    );
  },

  getAgentByApiKey(apiKey) {
    if (!apiKey) return null;
    return getAgentByApiKeyStmt.get(apiKey);
  },

  getAgent(agentId) {
    return getAgentByIdStmt.get(agentId);
  },

  listAgents() {
    return listAgentsStmt.all();
  },

  updateAgentHeartbeat(agentId, ip = null, addedEvents = 0) {
    return updateAgentHeartbeatStmt.run(ip, addedEvents, agentId);
  },

  revokeAgent(agentId) {
    return revokeAgentStmt.run(agentId);
  },

  getEventStats() {
    const total = countEventsStmt.get()?.count || 0;
    const bySource = countEventsBySourceStmt.all();
    const lastRow = getLastEventTimestampStmt.get();
    return {
      totalEvents: total,
      bySource,
      lastEventTimestamp: lastRow ? lastRow.timestamp : null
    };
  },

  // Audit
  getLatestAudit() {
    return getLatestAuditStmt.get();
  },

  insertAudit(entry) {
    return insertAuditStmt.run(
      entry.seq,
      entry.timestamp,
      entry.reviewer,
      entry.role,
      entry.action,
      entry.account || '',
      entry.computer || '',
      entry.rules || '',
      entry.decision || '',
      entry.note || '',
      entry.event_ids || '',
      entry.prev_hash,
      entry.hash
    );
  },

  getAuditTrail() {
    return getAuditTrailStmt.all();
  },

  setContainment(targetType, targetId, action, initiatedBy, reason, timestamp) {
    return upsertContainmentStmt.run(targetType, targetId, action, initiatedBy, reason, timestamp);
  },

  removeContainment(targetId) {
    return deleteContainmentStmt.run(targetId);
  },

  getActiveContainment() {
    return getActiveContainmentStmt.all();
  },

  // Network Devices & Hotspot Monitoring
  upsertNetworkDevice(dev) {
    const now = new Date().toISOString();
    return upsertNetworkDeviceStmt.run(
      dev.device_id,
      dev.ip,
      dev.mac || '',
      dev.hostname || '',
      dev.connection_status || 'Connected',
      dev.first_seen_at || now,
      dev.last_seen_at || now,
      dev.duration_seconds || 0,
      dev.bytes_sent || 0,
      dev.bytes_received || 0,
      dev.device_type || 'Unknown',
      dev.monitoring_status || 'Consent Pending',
      dev.consent_timestamp || null,
      dev.consent_notes || null,
      dev.interface_alias || '',
      dev.agent_enrolled ? 1 : 0,
      dev.api_key || null,
      dev.last_activity || now
    );
  },

  getNetworkDevice(deviceId) {
    if (!deviceId) return null;
    return getNetworkDeviceByIdStmt.get(deviceId);
  },

  getNetworkDeviceByIp(ip) {
    if (!ip) return null;
    return getNetworkDeviceByIpStmt.get(ip);
  },

  listNetworkDevices() {
    return listNetworkDevicesStmt.all();
  },

  updateDeviceConsent(deviceId, monitoringStatus, notes = null) {
    const timestamp = monitoringStatus === 'Approved' ? new Date().toISOString() : null;
    return updateDeviceConsentStmt.run(monitoringStatus, timestamp, notes, deviceId);
  },

  updateDeviceTraffic(deviceId, bytesSent = 0, bytesReceived = 0) {
    return updateDeviceTrafficStmt.run(bytesSent, bytesReceived, deviceId);
  },

  markStaleNetworkDevices(cutoffIso) {
    return markStaleDevicesStmt.run(cutoffIso);
  },

  insertNetworkEvent(ev) {
    const nowEpoch = typeof ev.ts === 'number' ? ev.ts : Date.now();
    const nowIso = ev.timestamp || new Date(nowEpoch).toISOString();
    return insertNetworkEventStmt.run(
      ev.event_id || `NET-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      ev.device_id,
      nowIso,
      nowEpoch,
      ev.source_ip,
      ev.dest_ip,
      ev.dest_port || null,
      ev.protocol || 'TCP',
      ev.domain || null,
      ev.bytes_transferred || 0,
      ev.event_type || 'connection',
      ev.severity || 'Routine',
      ev.rule_id || null,
      ev.explanation || '',
      ev.data_source || 'live_hotspot'
    );
  },

  getNetworkEvents({ deviceId = null, limit = 50 } = {}) {
    if (deviceId) {
      return selectDeviceNetworkEventsStmt.all(deviceId, limit);
    }
    return selectRecentNetworkEventsStmt.all(limit);
  },

  getNetworkStats() {
    const res = countNetworkDevicesStmt.get();
    return {
      total: res?.total || 0,
      connected: res?.connected || 0,
      approved: res?.approved || 0,
      pending: res?.pending || 0
    };
  },

  deleteNetworkDevice(deviceId) {
    if (!deviceId) return;
    const cleanId = String(deviceId).replace(/[^a-zA-Z0-9_\.\-]/g, '');
    db.exec(`DELETE FROM network_devices WHERE device_id = '${cleanId}'`);
    db.exec(`DELETE FROM network_events WHERE device_id = '${cleanId}'`);
  }
};
