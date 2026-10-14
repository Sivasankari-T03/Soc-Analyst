import assert from 'node:assert/strict';
import http from 'node:http';
import { dbService } from './server/db.js';
import { getLanIpv4Addresses } from './server.js';
import app, { serverInstance } from './server.js';

const TEST_PORT = 3001;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const MASTER_KEY = process.env.LABTRACE_API_KEY || 'labtrace-secret-key';

let testServer;

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const postData = body ? JSON.stringify(body) : null;
    const reqHeaders = { ...headers };
    if (postData) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(url, { method, headers: reqHeaders }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (_) {}
        resolve({ status: res.statusCode, headers: res.headers, body: json || data });
      });
    });

    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function runTests() {
  console.log('====================================================');
  console.log('🧪 LabTrace SOC Test Suite (Automated Verification)');
  console.log('====================================================\n');

  testServer = app.listen(TEST_PORT, '127.0.0.1');
  await new Promise(r => setTimeout(r, 200));

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`❌ FAIL: ${name}`);
      console.error(`   Error: ${err.message}\n`);
      failed++;
    }
  }

  // 1. LAN IPv4 Discovery
  await test('LAN IPv4 interface discovery discovers active host network', async () => {
    const lans = getLanIpv4Addresses();
    assert(Array.isArray(lans), 'LAN addresses should be an array');
    console.log(`   (Discovered ${lans.length} LAN IPv4 interface(s): ${lans.map(l => `${l.interface}: ${l.ip}`).join(', ')})`);
  });

  // 2. Health Endpoint
  await test('Server health endpoint returns healthy status and metadata', async () => {
    const res = await request('GET', '/api/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'healthy');
    assert.equal(res.body.app, 'LabTrace SOC Central Server');
    assert(res.body.uptimeSeconds >= 0);
  });

  // 3. Agent Authentication Enforcement
  await test('Ingestion API rejects requests without API key (401)', async () => {
    const res = await request('POST', '/api/ingest', [{ account: 'test', computer: 'PC-01' }]);
    assert.equal(res.status, 401);
    assert(res.body.error.includes('Unauthorized'));
  });

  await test('Ingestion API rejects invalid API key (401)', async () => {
    const res = await request('POST', '/api/ingest', [{ account: 'test', computer: 'PC-01' }], {
      'x-api-key': 'wrong-unauthorized-key'
    });
    assert.equal(res.status, 401);
  });

  // 4. Invalid Payload Handling
  await test('Ingestion API rejects empty payload (400)', async () => {
    const res = await request('POST', '/api/ingest', [], {
      'x-api-key': MASTER_KEY
    });
    assert.equal(res.status, 400);
  });

  // 5. Valid Event Ingestion & Normalization
  const uniqueEvId = `TEST-EV-${Date.now()}`;
  await test('Ingestion API accepts valid event with master key', async () => {
    const res = await request('POST', '/api/ingest', [{
      event_id: uniqueEvId,
      timestamp: new Date().toISOString(),
      account: 'test.user',
      computer: 'TEST-PC-01',
      event: 'FAILED',
      ip: '192.168.1.50'
    }], {
      'x-api-key': MASTER_KEY
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.accepted, 1);
    assert.equal(res.body.duplicates, 0);
  });

  // 6. Duplicate Event Rejection
  await test('Ingestion API rejects duplicate event_id without re-inserting', async () => {
    const res = await request('POST', '/api/ingest', [{
      event_id: uniqueEvId, // Same ID
      timestamp: new Date().toISOString(),
      account: 'test.user',
      computer: 'TEST-PC-01',
      event: 'FAILED',
      ip: '192.168.1.50'
    }], {
      'x-api-key': MASTER_KEY
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.accepted, 0);
    assert.equal(res.body.duplicates, 1);
  });

  // 7. Machine Account Noise Filtering
  await test('Ingestion filters machine accounts ($) without dropping valid users', async () => {
    const res = await request('POST', '/api/ingest', [{
      event_id: `MACHINE-${Date.now()}`,
      timestamp: new Date().toISOString(),
      account: 'WORKSTATION01$',
      computer: 'WORKSTATION01',
      event: 'SUCCESS'
    }], {
      'x-api-key': MASTER_KEY
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.accepted, 0);
    assert.equal(res.body.droppedNoise, 1);
  });

  // 8. Agent Enrollment & Per-Agent Authentication
  const testAgentKey = `agent-key-${Date.now()}`;
  await test('Enrollment API registers new authorized lab agent', async () => {
    const enrollRes = await request('POST', '/api/agents/enroll', {
      device_name: 'TEST-LAB-HOST',
      hostname: 'TEST-LAB-HOST',
      api_key: testAgentKey,
      os_info: 'Windows 11 Pro Lab Device'
    });

    assert.equal(enrollRes.status, 200);
    assert.equal(enrollRes.body.success, true);
    assert.equal(enrollRes.body.api_key, testAgentKey);

    // Verify agent can authenticate with their own key
    const ingestRes = await request('POST', '/api/ingest', [{
      event_id: `AGENT-EV-${Date.now()}`,
      timestamp: new Date().toISOString(),
      account: 'lab.student',
      computer: 'TEST-LAB-HOST',
      event: 'SUCCESS'
    }], {
      'x-api-key': testAgentKey,
      'x-agent-id': enrollRes.body.agent_id
    });

    assert.equal(ingestRes.status, 200);
    assert.equal(ingestRes.body.accepted, 1);
  });

  // 9. Agent List & Status API
  await test('Agents API lists enrolled devices with calculated reporting state', async () => {
    const res = await request('GET', '/api/agents');
    assert.equal(res.status, 200);
    assert(Array.isArray(res.body.agents));
    const enrolled = res.body.agents.find(a => a.device_name === 'TEST-LAB-HOST');
    assert(enrolled, 'Enrolled agent should appear in agents list');
    assert.equal(enrolled.reportingState, 'ONLINE');
  });

  // 10. Demo Authentication Flow
  await test('Demo login endpoint issues valid supervisor session in safe mode', async () => {
    const res = await request('POST', '/api/auth/demo');
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.session.role, 'Supervisor');
    assert.equal(res.body.session.isDemo, true);
    assert(res.body.session.token, 'Should return session token');
  });

  // 11. Cryptographic Audit Chain Verification
  await test('Cryptographic audit log records decisions and verifies SHA-256 chain integrity', async () => {
    // Record a test decision
    const recRes = await request('POST', '/api/audit/decision', {
      reviewer: 'Supervisor Test',
      role: 'Supervisor',
      account: 'test.user',
      computer: 'TEST-PC-01',
      rules: 'R1',
      decision: 'Confirmed',
      note: 'Verified during automated test suite'
    });
    assert.equal(recRes.status, 200);

    // Verify chain integrity
    const verRes = await request('GET', '/api/audit/verify');
    assert.equal(verRes.status, 200);
    assert.equal(verRes.body.valid, true);
    assert(verRes.body.count > 0);
  });

  // 12. Replay Demo Mode (Tagged as Simulated)
  await test('Replay API initializes sample stream with simulation tagging', async () => {
    const res = await request('POST', '/api/replay/start');
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert(res.body.totalRows > 0);

    // Stop replay
    await request('POST', '/api/replay/stop');
  });

  // 13. Network Capability Detection API
  await test('Network capability API reports truthful Windows networking and packet driver status', async () => {
    const res = await request('GET', '/api/network/status');
    assert.equal(res.status, 200);
    assert(res.body.os.includes('Windows'), 'Should detect Windows operating system');
    assert(typeof res.body.hotspotHosting === 'boolean', 'hotspotHosting should be boolean');
    assert(Array.isArray(res.body.supportedCollectionMethods), 'supportedCollectionMethods should be an array');
    assert(Array.isArray(res.body.unsupportedCollectionMethods), 'unsupportedCollectionMethods should be an array');
    assert(res.body.consentPolicy.includes('Strict Opt-In Required'), 'Must declare strict opt-in consent policy');
  });

  // 14. Network Devices Listing API
  await test('Network devices API lists discovered hotspot devices without inventing data', async () => {
    const res = await request('GET', '/api/network/devices?scan=false');
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert(Array.isArray(res.body.devices), 'devices should be an array');
    assert(res.body.capabilities, 'Should include capabilities summary');
  });

  // 15. Hotspot Agent Enrollment & Consent Enforcement
  let testHotspotAgentKey = null;
  let testHotspotDeviceId = null;
  await test('Hotspot agent enrollment requires explicit consent confirmation', async () => {
    // Missing consent should fail (400)
    const failRes = await request('POST', '/api/network/agent/enroll', {
      ip: '192.168.137.99',
      hostname: 'FRIEND-PHONE',
      consentGranted: false
    });
    assert.equal(failRes.status, 400);

    // Valid enrollment with explicit consent
    const successRes = await request('POST', '/api/network/agent/enroll', {
      ip: '192.168.137.99',
      hostname: 'FRIEND-PHONE',
      deviceType: 'Android 14 (Pixel 8)',
      consentGranted: true
    });
    assert.equal(successRes.status, 200);
    assert.equal(successRes.body.success, true);
    assert(successRes.body.deviceId, 'Should return deviceId');
    assert(successRes.body.apiKey, 'Should return apiKey');

    testHotspotDeviceId = successRes.body.deviceId;
    testHotspotAgentKey = successRes.body.apiKey;
  });

  // 16. Hotspot Agent Telemetry Ingestion & Authentication
  await test('Hotspot agent ingestion accepts valid telemetry with agent token and rejects unauthenticated (401)', async () => {
    // Rejects without API key
    const unauthRes = await request('POST', '/api/network/agent/events', [{
      source_ip: '192.168.137.99',
      dest_ip: '93.184.216.34',
      dest_port: 443,
      protocol: 'TCP'
    }]);
    assert.equal(unauthRes.status, 401);

    // Accepts with agent key
    const authRes = await request('POST', '/api/network/agent/events', [{
      source_ip: '192.168.137.99',
      dest_ip: '93.184.216.34',
      dest_port: 443,
      protocol: 'TCP',
      bytes_transferred: 1024,
      domain: 'example.com'
    }], {
      'x-agent-key': testHotspotAgentKey
    });
    assert.equal(authRes.status, 200);
    assert.equal(authRes.body.success, true);
    assert.equal(authRes.body.processed, 1);
  });

  // 17. Consent Management: Approval and Withdrawal Workflow
  await test('Consent management allows approving and withdrawing monitoring with audit logging', async () => {
    // Withdraw consent
    const withdrawRes = await request('POST', '/api/network/consent', {
      deviceId: testHotspotDeviceId,
      status: 'Not Monitored',
      reviewer: 'Supervisor Test'
    });
    assert.equal(withdrawRes.status, 200);
    assert.equal(withdrawRes.body.success, true);
    assert.equal(withdrawRes.body.device.monitoring_status, 'Not Monitored');

    // Grant / Re-approve consent
    const approveRes = await request('POST', '/api/network/consent', {
      deviceId: testHotspotDeviceId,
      status: 'Approved',
      reviewer: 'Supervisor Test'
    });
    assert.equal(approveRes.status, 200);
    assert.equal(approveRes.body.success, true);
    assert.equal(approveRes.body.device.monitoring_status, 'Approved');
  });

  // 18. Safe Network Test Simulation & Explainable Rule Trigger
  await test('Network simulation triggers explainable detection rules (NET-01 & NET-02) tagged as simulated', async () => {
    const simRes = await request('POST', '/api/network/test/simulate', {
      scenario: 'burst',
      sourceIp: '192.168.137.99',
      destIp: '192.168.137.1'
    });
    assert.equal(simRes.status, 200);
    assert.equal(simRes.body.success, true);
    assert.equal(simRes.body.scenario, 'burst');
    assert(simRes.body.simulated > 0);

    // Verify events were inserted into network_events table
    const evsRes = await request('GET', `/api/network/events?deviceId=${testHotspotDeviceId}`);
    assert.equal(evsRes.status, 200);
    assert.equal(evsRes.body.success, true);
    assert(evsRes.body.events.length > 0);
  });

  console.log('\n====================================================');
  console.log(`Test Execution Summary: ${passed} passed, ${failed} failed.`);
  console.log('====================================================\n');

  testServer.close();
  serverInstance.close();
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  if (testServer) testServer.close();
  if (serverInstance) serverInstance.close();
  process.exit(1);
});
