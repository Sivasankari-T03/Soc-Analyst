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
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(ts_epoch);
  CREATE INDEX IF NOT EXISTS idx_events_account ON events(account);
  CREATE INDEX IF NOT EXISTS idx_events_computer ON events(computer);

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
`);

// Prepared statements for high throughput
const insertEventStmt = db.prepare(`
  INSERT OR IGNORE INTO events 
  (event_id, timestamp, ts_epoch, account, computer, ip, event, logon_type, department_case, is_noise, enriched_geo, enriched_threat)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const selectRecentStmt = db.prepare(`
  SELECT event_id, timestamp, ts_epoch as ts, account, computer, ip, event, logon_type, department_case, enriched_geo, enriched_threat
  FROM events
  WHERE ts_epoch >= ?
  ORDER BY ts_epoch ASC
  LIMIT ?
`);

const selectAllRecentStmt = db.prepare(`
  SELECT event_id, timestamp, ts_epoch as ts, account, computer, ip, event, logon_type, department_case, enriched_geo, enriched_threat
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
      threatStr
    );
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
  }
};
