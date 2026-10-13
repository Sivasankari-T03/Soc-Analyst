// Windows Logon Types reference:
// 2  = Interactive (Local console logon)
// 3  = Network (SMB/file share/remote auth)
// 4  = Batch (Scheduled task)
// 5  = Service (Service startup)
// 7  = Unlock (Workstation unlock)
// 8  = NetworkCleartext
// 9  = NewCredentials (RunAs)
// 10 = RemoteInteractive (RDP)
// 11 = CachedInteractive (Cached domain logon)

const LOGON_TYPES = {
  '2': 'Interactive (Console)',
  '3': 'Network (SMB/RPC)',
  '4': 'Batch Task',
  '5': 'Service Account',
  '7': 'Screen Unlock',
  '8': 'Network Cleartext',
  '9': 'RunAs Credentials',
  '10': 'Remote Desktop (RDP)',
  '11': 'Cached Interactive',
  'Interactive': 'Interactive (Console)',
  'RDP': 'Remote Desktop (RDP)',
  'RemoteInteractive': 'Remote Desktop (RDP)',
  'Network': 'Network (SMB/RPC)',
  'Unlock': 'Screen Unlock'
};

const SYSTEM_ACCOUNTS = new Set([
  'anonymous logon',
  'nt authority\\system',
  'nt authority\\local service',
  'nt authority\\network service',
  'system',
  'local service',
  'network service',
  'dwm-1',
  'dwm-2',
  'font driver host'
]);

export function analyzeNoise(event) {
  const accountRaw = String(event.account || '').trim();
  const accountLower = accountRaw.toLowerCase();
  
  // 1. Machine Account Check (Active Directory / Windows machine accounts end with $)
  if (accountRaw.endsWith('$')) {
    return {
      drop: true,
      reason: 'Machine account (ends with $)',
      isNoise: true,
      normalizedAccount: accountRaw,
      logonTypeLabel: 'Machine'
    };
  }

  // 2. Windows Internal System Accounts
  if (SYSTEM_ACCOUNTS.has(accountLower)) {
    return {
      drop: true,
      reason: 'Windows system service account',
      isNoise: true,
      normalizedAccount: accountRaw,
      logonTypeLabel: 'System'
    };
  }

  // 3. Normalize Logon Type
  let rawType = String(event.logon_type || event.logonType || '').trim();
  let logonTypeLabel = LOGON_TYPES[rawType] || (rawType ? `Type ${rawType}` : 'Interactive');

  // 4. Service Account Check (common routine prefix)
  const isService = /^svc[\._]|^service[\._]|\bbot\b|^backup/i.test(accountRaw);

  return {
    drop: false,
    reason: isService ? 'Routine service account pattern' : 'Standard user account',
    isNoise: false,
    isService,
    normalizedAccount: accountRaw,
    logonTypeLabel
  };
}
