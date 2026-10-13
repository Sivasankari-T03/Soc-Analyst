import { createHash } from 'node:crypto';
import { dbService } from './db.js';

const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function computeEntryHash(entry) {
  const content = [
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
    entry.prev_hash
  ].join('|');

  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export const auditService = {
  record({ reviewer, role, action, account, computer, rules, decision, note, event_ids }) {
    const latest = dbService.getLatestAudit();
    const seq = latest ? latest.seq + 1 : 1;
    const prev_hash = latest ? latest.hash : GENESIS_PREV_HASH;
    const timestamp = new Date().toISOString();

    const entryToHash = {
      seq,
      timestamp,
      reviewer: reviewer || 'system',
      role: role || 'System',
      action: action || 'DECISION',
      account: account || '',
      computer: computer || '',
      rules: rules || '',
      decision: decision || '',
      note: note || '',
      event_ids: event_ids || '',
      prev_hash
    };

    const hash = computeEntryHash(entryToHash);

    const fullEntry = {
      ...entryToHash,
      hash
    };

    dbService.insertAudit(fullEntry);
    return fullEntry;
  },

  getAll() {
    return dbService.getAuditTrail();
  },

  verifyChain() {
    const entries = dbService.getAuditTrail();
    if (!entries.length) {
      return {
        valid: true,
        count: 0,
        message: 'Audit log is currently empty. Chain is ready.'
      };
    }

    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Check sequence number integrity
      if (entry.seq !== i + 1) {
        return {
          valid: false,
          error: `Sequence mismatch at index ${i}: expected seq ${i + 1}, found ${entry.seq}`,
          brokenSeq: entry.seq
        };
      }

      // Check backward hash link
      if (entry.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          error: `Broken hash link at entry #${entry.seq}: stored prev_hash does not match preceding block's hash`,
          brokenSeq: entry.seq
        };
      }

      // Recompute and verify the entry's own SHA-256 hash
      const computedHash = computeEntryHash(entry);
      if (computedHash !== entry.hash) {
        return {
          valid: false,
          error: `Tamper detected at entry #${entry.seq}: cryptographic hash recalculation failed`,
          brokenSeq: entry.seq
        };
      }

      expectedPrevHash = entry.hash;
    }

    return {
      valid: true,
      count: entries.length,
      headHash: entries[entries.length - 1].hash,
      genesisHash: entries[0].hash,
      message: `All ${entries.length} audit entries cryptographically validated against SHA-256 chain.`
    };
  }
};
