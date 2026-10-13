import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { dbService } from './db.js';
import { auditService } from './audit.js';

const execAsync = promisify(exec);

// Safety configuration: By default, in development/evaluation mode we log and record safe dry-run commands.
// Set EXECUTE_REAL_ACTIONS=true in .env only in production environments with proper AD / EDR privileges.
const EXECUTE_REAL_ACTIONS = process.env.EXECUTE_REAL_ACTIONS === 'true';

export const playbooks = {
  async lock({ account, reviewer, role, note, supervisorApproved }) {
    if (!account) throw new Error('Account parameter is required');

    // Strict safety check: Never lock without supervisor authorization
    if (role !== 'Supervisor' || !supervisorApproved) {
      throw new Error('Lock action requires explicit Supervisor authorization and confirmation note.');
    }

    const cleanAccount = String(account).replace(/[^a-zA-Z0-9_\.\-]/g, '');
    let executionResult = 'Contained in LabTrace state (Safe Mode)';

    if (EXECUTE_REAL_ACTIONS) {
      try {
        // Real PowerShell Active Directory command
        const cmd = `powershell.exe -NoProfile -Command "Disable-ADAccount -Identity '${cleanAccount}' -ErrorAction Stop"`;
        const { stdout } = await execAsync(cmd);
        executionResult = `Executed Disable-ADAccount: ${stdout.trim() || 'Success'}`;
      } catch (err) {
        // Fallback to local Windows account if AD module is absent
        try {
          const fallback = `net user "${cleanAccount}" /active:no`;
          await execAsync(fallback);
          executionResult = `Executed local net user /active:no`;
        } catch (netErr) {
          executionResult = `Execution warning (check AD privileges): ${err.message}`;
        }
      }
    }

    // Persist containment in server DB
    dbService.setContainment('account', cleanAccount, 'locked', reviewer, note, new Date().toISOString());

    // Record into cryptographic audit trail
    const auditEntry = auditService.record({
      reviewer,
      role,
      action: 'PLAYBOOK_LOCK_ACCOUNT',
      account: cleanAccount,
      computer: '',
      rules: 'PLAYBOOK',
      decision: 'LOCKED',
      note: `[Supervisor Approved] ${note} (${executionResult})`,
      event_ids: ''
    });

    return {
      success: true,
      action: 'lock',
      account: cleanAccount,
      result: executionResult,
      auditHash: auditEntry.hash
    };
  },

  async isolate({ computer, reviewer, role, note, supervisorApproved }) {
    if (!computer) throw new Error('Computer parameter is required');

    // Strict safety check: Supervisor authorization required
    if (role !== 'Supervisor' || !supervisorApproved) {
      throw new Error('Isolation action requires explicit Supervisor authorization.');
    }

    const cleanComputer = String(computer).replace(/[^a-zA-Z0-9_\.\-]/g, '');
    let executionResult = 'Workstation isolated in LabTrace state (Safe Mode)';

    if (EXECUTE_REAL_ACTIONS) {
      try {
        // Real Windows Firewall isolation rule
        const cmd = `netsh advfirewall firewall add rule name="LabTrace_SOC_Isolation" dir=in action=block remoteip=any`;
        const { stdout } = await execAsync(cmd);
        executionResult = `Network isolation rule applied via netsh: ${stdout.trim()}`;
      } catch (err) {
        executionResult = `Firewall rule execution warning: ${err.message}`;
      }
    }

    // Persist in DB
    dbService.setContainment('computer', cleanComputer, 'isolated', reviewer, note, new Date().toISOString());

    // Record into cryptographic audit trail
    const auditEntry = auditService.record({
      reviewer,
      role,
      action: 'PLAYBOOK_ISOLATE_HOST',
      account: '',
      computer: cleanComputer,
      rules: 'PLAYBOOK',
      decision: 'ISOLATED',
      note: `[Supervisor Approved] ${note} (${executionResult})`,
      event_ids: ''
    });

    return {
      success: true,
      action: 'isolate',
      computer: cleanComputer,
      result: executionResult,
      auditHash: auditEntry.hash
    };
  },

  async reset({ account, reviewer, role, note }) {
    if (!account) throw new Error('Account parameter is required');
    const cleanAccount = String(account).replace(/[^a-zA-Z0-9_\.\-]/g, '');
    let executionResult = 'Password reset flag staged in LabTrace (Safe Mode)';

    if (EXECUTE_REAL_ACTIONS) {
      try {
        // Force change password at next logon
        const cmd = `powershell.exe -NoProfile -Command "Set-ADUser -Identity '${cleanAccount}' -ChangePasswordAtLogon $true"`;
        await execAsync(cmd);
        executionResult = 'Set-ADUser ChangePasswordAtLogon set to $true';
      } catch (err) {
        executionResult = `Password reset dispatch warning: ${err.message}`;
      }
    }

    // Record in audit log
    const auditEntry = auditService.record({
      reviewer,
      role,
      action: 'PLAYBOOK_PASSWORD_RESET',
      account: cleanAccount,
      computer: '',
      rules: 'PLAYBOOK',
      decision: 'RESET_REQUIRED',
      note: note || 'Password reset requested at next logon',
      event_ids: ''
    });

    return {
      success: true,
      action: 'reset',
      account: cleanAccount,
      result: executionResult,
      auditHash: auditEntry.hash
    };
  },

  async escalate({ incident, reviewer, role, note, channel }) {
    const payload = {
      timestamp: new Date().toISOString(),
      reviewer,
      role,
      channel: channel || 'Tier-2 SOC Team',
      note: note || 'Manual analyst escalation',
      incident: incident || {}
    };

    let webhookStatus = 'Logged to SOC event log (No external webhook configured)';

    const webhookUrl = process.env.WEBHOOK_URL;
    if (webhookUrl) {
      try {
        const resp = await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: `🚨 *LabTrace SOC Escalation* by ${reviewer} (${role})\n` +
                  `*Target:* ${incident?.account || 'Unknown'} @ ${incident?.computer || 'Unknown'}\n` +
                  `*Rules:* ${incident?.reasons?.join(', ') || 'Review'}\n` +
                  `*Note:* ${note || 'Immediate triage requested'}`
          })
        });
        webhookStatus = `Dispatched to webhook (${resp.status} ${resp.statusText})`;
      } catch (err) {
        webhookStatus = `Webhook dispatch failed: ${err.message}`;
      }
    }

    // Record in audit log
    const auditEntry = auditService.record({
      reviewer,
      role,
      action: 'PLAYBOOK_ESCALATE',
      account: incident?.account || '',
      computer: incident?.computer || '',
      rules: incident?.reasons?.join('+') || 'ESCALATED',
      decision: 'ESCALATED',
      note: `[Escalation] ${note || 'Forwarded to Tier-2'} (${webhookStatus})`,
      event_ids: incident?.eventIds || ''
    });

    return {
      success: true,
      action: 'escalate',
      result: webhookStatus,
      payload,
      auditHash: auditEntry.hash
    };
  },

  async release({ targetId, targetType, reviewer, role, note }) {
    if (role !== 'Supervisor') {
      throw new Error('Only Supervisors can release containment.');
    }

    dbService.removeContainment(targetId);

    const auditEntry = auditService.record({
      reviewer,
      role,
      action: 'PLAYBOOK_RELEASE_CONTAINMENT',
      account: targetType === 'account' ? targetId : '',
      computer: targetType === 'computer' ? targetId : '',
      rules: 'PLAYBOOK',
      decision: 'RELEASED',
      note: note || `Released containment for ${targetId}`,
      event_ids: ''
    });

    return {
      success: true,
      action: 'release',
      targetId,
      auditHash: auditEntry.hash
    };
  },

  getStatus() {
    const active = dbService.getActiveContainment();
    const lockedAccounts = active.filter(a => a.target_type === 'account').map(a => a.target_id);
    const isolatedComputers = active.filter(a => a.target_type === 'computer').map(a => a.target_id);
    return {
      lockedAccounts,
      isolatedComputers,
      details: active
    };
  }
};
