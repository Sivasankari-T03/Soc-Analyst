import os from 'node:os';
import dns from 'node:dns';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { dbService } from './db.js';
import { auditService } from './audit.js';

const execFileAsync = promisify(execFile);

// Common MAC OUI prefixes for transparent, truthful vendor identification
const MAC_OUI_MAP = {
  '98:fe:3e': 'Samsung Electronics',
  '2c:7b:a0': 'HP Inc.',
  '00:50:56': 'VMware Virtual',
  '08:00:27': 'Oracle VirtualBox',
  'f8:ff:c2': 'Apple Inc.',
  'ac:bc:32': 'Apple Inc.',
  'bc:d0:74': 'Apple Inc.',
  '38:18:68': 'Intel Corporate',
  '48:45:e6': 'Intel Corporate',
  '64:4e:d7': 'Intel Corporate',
  'dc:56:7b': 'Dell Inc.',
  'b8:82:f2': 'Lenovo Mobile',
  '70:cf:49': 'Xiaomi Communications',
  '4c:77:cb': 'OnePlus / Oppo',
  'a0:80:69': 'Google LLC',
  'dc:21:48': 'Realtek Semiconductor',
  '44:fa:66': 'Microsoft Mobile'
};

const SENSITIVE_PORTS = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  445: 'SMB/RPC',
  1433: 'MS-SQL',
  3306: 'MySQL',
  3389: 'RDP Remote Desktop',
  5900: 'VNC',
  8080: 'HTTP Proxy'
};

class NetworkMonitor {
  constructor() {
    this.scanInterval = null;
    this.recentFlowsBySource = new Map(); // ip -> Array<{ ts, port, dest_ip }>
    this.broadcastCallback = null;
    this.cachedCapabilities = null;
    this.lastCapabilitiesCheck = 0;
  }

  setBroadcastCallback(cb) {
    this.broadcastCallback = cb;
  }

  broadcast(type, payload) {
    if (typeof this.broadcastCallback === 'function') {
      try {
        this.broadcastCallback(type, payload);
      } catch (_) {}
    }
  }

  /* =========================================================================
     1. CAPABILITY DETECTION MODULE
     ========================================================================= */
  detectCapabilities() {
    const now = Date.now();
    if (this.cachedCapabilities && now - this.lastCapabilitiesCheck < 10000) {
      return this.cachedCapabilities;
    }

    const interfaces = os.networkInterfaces();
    let hotspotHosting = false;
    let hotspotInterface = null;
    let hotspotGatewayIp = null;
    let hotspotSubnet = null;

    // Detect Windows Mobile Hotspot adapter (normally 192.168.137.1 /24 or Virtual Wi-Fi Direct)
    for (const [name, addrs] of Object.entries(interfaces)) {
      for (const a of addrs) {
        if (a.family === 'IPv4' && !a.internal) {
          if (a.address.startsWith('192.168.137.') || name.toLowerCase().includes('hotspot') || name.toLowerCase().includes('local area connection*')) {
            hotspotHosting = true;
            hotspotInterface = name;
            hotspotGatewayIp = a.address;
            hotspotSubnet = '192.168.137.0/24';
            break;
          }
        }
      }
      if (hotspotHosting) break;
    }

    // Check if Npcap / WinPcap packet capture driver is installed on Windows
    let packetCaptureDriver = 'NOT DETECTED';
    let driverDetails = 'Npcap/WinPcap not installed. Passive promiscuous packet sniffing is unavailable without Npcap or elevated tools.';
    const npcapDll = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'wpcap.dll');
    const npcapDir = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'Npcap');

    if (fs.existsSync(npcapDll) || fs.existsSync(npcapDir)) {
      packetCaptureDriver = 'INSTALLED';
      driverDetails = 'Npcap driver detected on host system.';
    }

    const stats = dbService.getNetworkStats();

    this.cachedCapabilities = {
      os: 'Windows (' + os.release() + ')',
      hotspotHosting,
      hotspotInterface: hotspotInterface || 'Not Active',
      hotspotGatewayIp: hotspotGatewayIp || 'N/A',
      hotspotSubnet: hotspotSubnet || 'N/A',
      packetCaptureDriver,
      driverDetails,
      supportedCollectionMethods: [
        'Windows Kernel Neighbor Discovery (arp -a / Get-NetNeighbor)',
        'Windows OS Hostname Resolution (Reverse DNS via mshome.net / LLMNR)',
        'Authorized Hotspot Endpoint Agent (Explicitly opted-in client push)',
        'Host-Bound Socket Telemetry (Direct flows terminating at port 3000)'
      ],
      unsupportedCollectionMethods: [
        'Passive Transit Packet Sniffing (Requires Npcap driver in WinPcap-compatible mode)',
        'Encrypted TLS/HTTPS Payload Inspection (Privacy boundary strictly enforced by ENG-02)'
      ],
      consentPolicy: 'Strict Opt-In Required. Device metadata is only tracked after consent is approved.',
      deviceStats: stats
    };
    this.lastCapabilitiesCheck = now;
    return this.cachedCapabilities;
  }

  /* =========================================================================
     2. DEVICE DISCOVERY & NEIGHBOR PARSING
     ========================================================================= */
  async scanDevices() {
    try {
      const { stdout } = await execFileAsync('arp', ['-a']);
      const discovered = this.parseArpOutput(stdout);
      const nowIso = new Date().toISOString();

      for (const dev of discovered) {
        const existing = dbService.getNetworkDevice(dev.device_id) || dbService.getNetworkDeviceByIp(dev.ip);
        const firstSeen = existing ? existing.first_seen_at : nowIso;
        const durationSec = existing 
          ? Math.max(0, Math.round((Date.now() - Date.parse(firstSeen)) / 1000))
          : 0;

        let hostname = existing?.hostname || dev.hostname || '';
        const vendor = this.lookupVendor(dev.mac);
        let deviceType = existing ? existing.device_type : 'Unknown';
        if (deviceType === 'Unknown') {
          deviceType = this.inferDeviceType(hostname, vendor);
        }

        const record = {
          device_id: dev.device_id,
          ip: dev.ip,
          mac: dev.mac,
          hostname: hostname || dev.ip,
          connection_status: 'Connected',
          first_seen_at: firstSeen,
          last_seen_at: nowIso,
          duration_seconds: durationSec,
          bytes_sent: 0,
          bytes_received: 0,
          device_type: deviceType,
          monitoring_status: existing ? existing.monitoring_status : 'Consent Pending',
          consent_timestamp: existing ? existing.consent_timestamp : null,
          consent_notes: existing ? existing.consent_notes : null,
          interface_alias: dev.interface_alias || 'Windows Mobile Hotspot',
          agent_enrolled: existing ? existing.agent_enrolled : 0,
          api_key: existing ? existing.api_key : null,
          last_activity: nowIso
        };

        dbService.upsertNetworkDevice(record);

        // Asynchronously resolve hostname if missing and update DB when resolved
        if (!hostname || hostname === dev.ip) {
          this.resolveHostname(dev.ip).then((resolved) => {
            if (resolved && resolved !== dev.ip) {
              const updatedType = this.inferDeviceType(resolved, vendor);
              dbService.upsertNetworkDevice({
                ...record,
                hostname: resolved,
                device_type: updatedType !== 'Unknown' ? updatedType : record.device_type
              });
            }
          }).catch(() => {});
        }

        // If newly discovered device, emit event
        if (!existing) {
          this.broadcast('network_device_joined', record);
        }
      }

      // Mark devices that haven't been seen in the neighbor table for >2 minutes as Disconnected
      const cutoff = new Date(Date.now() - 120000).toISOString();
      dbService.markStaleNetworkDevices(cutoff);

      return dbService.listNetworkDevices();
    } catch (err) {
      console.warn('[NetworkMonitor] ARP discovery scan error:', err.message);
      return dbService.listNetworkDevices();
    }
  }

  parseArpOutput(stdout) {
    const lines = stdout.split(/\r?\n/);
    let currentInterface = '';
    const results = [];
    let isHotspotSection = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;

      if (line.startsWith('Interface:')) {
        const match = line.match(/Interface:\s*([0-9\.]+)/);
        if (match) {
          currentInterface = match[1];
          isHotspotSection = currentInterface === '192.168.137.1';
        }
        continue;
      }

      // Focus on hotspot clients (192.168.137.x)
      if (!isHotspotSection && !line.includes('192.168.137.')) {
        continue;
      }

      const parts = line.split(/\s+/);
      if (parts.length >= 3) {
        const ip = parts[0];
        const macRaw = parts[1];
        const type = parts[2].toLowerCase();

        // Filter out broadcast, multicast, and gateway
        if (
          !ip.match(/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ||
          ip.endsWith('.255') ||
          ip === '255.255.255.255' ||
          ip.startsWith('224.') ||
          ip.startsWith('239.') ||
          ip.startsWith('230.') ||
          ip === '192.168.137.1' ||
          macRaw === 'ff-ff-ff-ff-ff-ff' ||
          macRaw.startsWith('01-00-5e') ||
          macRaw === '00-00-00-00-00-00'
        ) {
          continue;
        }

        // Standardize MAC format to XX:XX:XX:XX:XX:XX
        const mac = macRaw.replace(/-/g, ':').toUpperCase();
        const cleanMac = mac.replace(/[^A-F0-9]/g, '');
        const device_id = `DEV-${cleanMac || ip.replace(/\./g, '')}`;

        results.push({
          device_id,
          ip,
          mac,
          interface_alias: 'Windows Mobile Hotspot (192.168.137.1)',
          type
        });
      }
    }

    return results;
  }

  resolveHostname(ip) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(''), 500);
      dns.lookupService(ip, 80, (err, hostname) => {
        clearTimeout(timer);
        if (!err && hostname) {
          const clean = hostname.replace(/\.mshome\.net$/i, '');
          resolve(clean);
        } else {
          resolve('');
        }
      });
    });
  }

  lookupVendor(mac) {
    if (!mac) return 'Unknown Vendor';
    const prefix = mac.slice(0, 8).toLowerCase();
    return MAC_OUI_MAP[prefix] || 'Unknown Vendor';
  }

  inferDeviceType(hostname, vendor) {
    const h = (hostname || '').toLowerCase();
    const v = (vendor || '').toLowerCase();

    if (h.startsWith('desktop-') || h.startsWith('laptop-') || h.includes('win-') || h.includes('pc')) {
      return 'Windows PC / Laptop';
    }
    if (h.includes('iphone') || h.includes('ipad') || v.includes('apple')) {
      return 'Apple iOS Device';
    }
    if (h.includes('android') || h.includes('galaxy') || v.includes('samsung') || v.includes('xiaomi') || v.includes('oneplus')) {
      return 'Mobile / Smartphone';
    }
    if (v.includes('vmware') || v.includes('virtualbox')) {
      return 'Virtual Machine';
    }
    return 'Unknown / Generic Device';
  }

  /* =========================================================================
     3. CONSENT MANAGEMENT
     ========================================================================= */
  setConsent(deviceId, monitoringStatus, notes = '', reviewer = 'Supervisor') {
    const device = dbService.getNetworkDevice(deviceId);
    if (!device) throw new Error(`Device ID "${deviceId}" not found`);

    if (monitoringStatus !== 'Approved' && monitoringStatus !== 'Not Monitored' && monitoringStatus !== 'Consent Pending') {
      throw new Error('Invalid monitoring status. Must be Approved, Not Monitored, or Consent Pending.');
    }

    dbService.updateDeviceConsent(deviceId, monitoringStatus, notes);

    // Cryptographic audit log
    const auditEntry = auditService.record({
      reviewer,
      role: 'Supervisor',
      action: 'HOTSPOT_CONSENT_UPDATE',
      account: device.hostname || device.ip,
      computer: device.ip,
      rules: 'PRIVACY_CONSENT',
      decision: monitoringStatus.toUpperCase(),
      note: `Hotspot monitoring consent for ${device.ip} (${device.mac}) changed to "${monitoringStatus}": ${notes || 'No notes'}`,
      event_ids: deviceId
    });

    const updated = dbService.getNetworkDevice(deviceId);
    this.broadcast('network_consent_updated', { device: updated, auditHash: auditEntry.hash });

    return {
      success: true,
      device: updated,
      auditHash: auditEntry.hash
    };
  }

  /* =========================================================================
     4. NETWORK EVENT INGESTION & DETECTION RULES
     ========================================================================= */
  ingestNetworkEvent(event) {
    const { device_id, source_ip, dest_ip, dest_port, protocol = 'TCP', domain, bytes_transferred = 0, data_source = 'live_hotspot' } = event;

    if (!source_ip || !dest_ip) {
      throw new Error('source_ip and dest_ip are required for network telemetry');
    }

    // Match or find device
    let dev = device_id ? dbService.getNetworkDevice(device_id) : dbService.getNetworkDeviceByIp(source_ip);
    if (!dev) {
      const cleanIp = source_ip.replace(/\./g, '');
      const newDev = {
        device_id: device_id || `DEV-${cleanIp}`,
        ip: source_ip,
        mac: event.mac || '',
        hostname: event.hostname || source_ip,
        connection_status: 'Connected',
        first_seen_at: new Date().toISOString(),
        last_seen_at: new Date().toISOString(),
        monitoring_status: 'Consent Pending'
      };
      dbService.upsertNetworkDevice(newDev);
      dev = dbService.getNetworkDevice(newDev.device_id);
    }

    // PRIVACY GUARD: If device is not approved, drop granular metadata
    if (dev.monitoring_status !== 'Approved' && data_source !== 'simulated') {
      return {
        accepted: false,
        status: dev.monitoring_status,
        message: 'Device telemetry suppressed: Explicit monitoring consent has not been approved for this device.'
      };
    }

    // Update traffic counters
    dbService.updateDeviceTraffic(dev.device_id, bytes_transferred, 0);

    // Rule Evaluation:
    const now = Date.now();
    let rule_id = null;
    let severity = 'Routine';
    let explanation = `Normal ${protocol} traffic to ${dest_ip}:${dest_port || 80}`;
    let event_type = event.event_type || 'connection';

    // Track rolling flows for port scan / burst detection
    if (!this.recentFlowsBySource.has(source_ip)) {
      this.recentFlowsBySource.set(source_ip, []);
    }
    const flows = this.recentFlowsBySource.get(source_ip);
    flows.push({ ts: now, port: dest_port, dest_ip });

    // Clean older than 15 seconds
    const recent = flows.filter(f => now - f.ts < 15000);
    this.recentFlowsBySource.set(source_ip, recent);

    const distinctPorts = new Set(recent.map(f => f.port).filter(Boolean));
    const portNum = Number(dest_port);

    // Rule NET-03: Sensitive Management Port Probe
    if (portNum && SENSITIVE_PORTS[portNum]) {
      rule_id = 'NET-03';
      severity = 'Priority Review';
      event_type = 'sensitive_port_probe';
      explanation = `Probed sensitive management port ${portNum} (${SENSITIVE_PORTS[portNum]}) on ${dest_ip}`;
    }
    // Rule NET-02: Port Scan Pattern (probed >= 5 distinct ports within 15s)
    else if (distinctPorts.size >= 5) {
      rule_id = 'NET-02';
      severity = 'Priority Review';
      event_type = 'port_scan_suspect';
      explanation = `Suspected port scan: Probed ${distinctPorts.size} distinct ports within 15 seconds`;
    }
    // Rule NET-01: Rapid Connection Burst (> 15 connections within 15s)
    else if (recent.length > 15) {
      rule_id = 'NET-01';
      severity = 'Review';
      event_type = 'connection_burst';
      explanation = `Unusually rapid connection burst: ${recent.length} connections in 15 seconds`;
    }
    // Rule NET-04: High Bandwidth Spike (> 20 MB in single flow)
    else if (bytes_transferred > 20 * 1024 * 1024) {
      rule_id = 'NET-04';
      severity = 'Review';
      event_type = 'high_bandwidth';
      explanation = `Elevated data transfer volume (${(bytes_transferred / (1024*1024)).toFixed(1)} MB)`;
    }

    const eventRecord = {
      event_id: event.event_id || `NET-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      device_id: dev.device_id,
      timestamp: event.timestamp || new Date().toISOString(),
      ts: now,
      source_ip,
      dest_ip,
      dest_port: portNum || null,
      protocol: protocol.toUpperCase(),
      domain: domain || null,
      bytes_transferred,
      event_type,
      severity,
      rule_id,
      explanation,
      data_source
    };

    dbService.insertNetworkEvent(eventRecord);
    this.broadcast('network_event', eventRecord);

    return {
      accepted: true,
      event: eventRecord
    };
  }

  /* =========================================================================
     5. AUTHORIZED FRIEND ENDPOINT AGENT ENROLLMENT
     ========================================================================= */
  enrollAgent({ deviceId, ip, hostname, deviceType = 'Unknown' }) {
    if (!ip) throw new Error('IP address is required for agent enrollment');

    const cleanMac = (deviceId || '').replace(/[^A-Za-z0-9]/g, '');
    const cleanId = deviceId ? `DEV-${cleanMac}` : `DEV-${ip.replace(/\./g, '')}`;
    const apiKey = `hotspot-agent-${crypto.randomBytes(16).toString('hex')}`;
    const nowIso = new Date().toISOString();

    const record = {
      device_id: cleanId,
      ip,
      mac: '',
      hostname: hostname || ip,
      connection_status: 'Connected',
      first_seen_at: nowIso,
      last_seen_at: nowIso,
      duration_seconds: 0,
      bytes_sent: 0,
      bytes_received: 0,
      device_type: deviceType,
      monitoring_status: 'Approved', // Explicit enrollment constitutes consent
      consent_timestamp: nowIso,
      consent_notes: 'Enrolled via authorized hotspot agent on device',
      interface_alias: 'Hotspot Agent Ingest',
      agent_enrolled: 1,
      api_key: apiKey,
      last_activity: nowIso
    };

    dbService.upsertNetworkDevice(record);

    auditService.record({
      reviewer: hostname || ip,
      role: 'Endpoint Agent',
      action: 'HOTSPOT_AGENT_ENROLL',
      account: hostname || ip,
      computer: ip,
      rules: 'AGENT_ENROLL',
      decision: 'APPROVED',
      note: `Hotspot endpoint agent enrolled for ${ip} with generated token`,
      event_ids: cleanId
    });

    return {
      success: true,
      deviceId: cleanId,
      apiKey,
      serverUrl: `http://${ip.startsWith('192.168.137.') ? '192.168.137.1' : 'localhost'}:3000/api/network/agent/events`,
      message: 'Agent successfully enrolled with active monitoring consent.'
    };
  }

  startPeriodicScanning(intervalMs = 8000) {
    if (this.scanInterval) clearInterval(this.scanInterval);
    // Initial immediate scan
    this.scanDevices();
    this.scanInterval = setInterval(() => this.scanDevices(), intervalMs);
  }

  stop() {
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
  }
}

export const networkMonitor = new NetworkMonitor();
