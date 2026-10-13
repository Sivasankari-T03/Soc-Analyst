import http from 'node:http';

const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000/api/ingest';
const API_KEY = process.env.API_KEY || 'labtrace-secret-key';

const USERS = ['a.kumar', 'r.priya', 'm.arun', 's.divya', 'k.vikram', 't.nisha', 'guest_lab', 'svc.backup', 'admin.lab'];
const COMPUTERS = ['PC-01', 'PC-02', 'PC-03', 'PC-04', 'PC-05', 'PC-06', 'PC-07', 'PC-08', 'PC-10', 'PC-11', 'PC-12'];

const EXTERNAL_IPS = [
  '185.220.101.4', // Known Tor Exit Node
  '45.155.205.9',  // Known GreyNoise Scanner
  '194.26.29.112', // Known Brute Force IP
  '141.98.11.11',  // Scanner
  '203.0.113.42'   // External internet host
];

function randomInternalIp() {
  return `10.20.${1 + Math.floor(Math.random() * 8)}.${10 + Math.floor(Math.random() * 200)}`;
}

let counter = Date.now();

function postEvents(events) {
  const data = JSON.stringify(events);
  const url = new URL(SERVER_URL);

  const req = http.request(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
      'x-api-key': API_KEY
    }
  }, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      console.log(`[${new Date().toLocaleTimeString()}] Sent ${events.length} event(s) -> Status ${res.statusCode} (Accepted: ${events.length})`);
    });
  });

  req.on('error', (err) => {
    console.error(`[Connection Error] Could not connect to ${SERVER_URL}: ${err.message}`);
  });

  req.write(data);
  req.end();
}

function makeEvent(account, computer, event, ip, logonType = '2') {
  counter++;
  return {
    event_id: `EV-FEED-${counter}`,
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
    account,
    computer,
    ip,
    event,
    logon_type: logonType,
    department_case: 'FEEDER'
  };
}

console.log('====================================================');
console.log('  LabTrace Realistic Traffic Feeder                 ');
console.log(`  Sending live events to: ${SERVER_URL}             `);
console.log('====================================================');

// Periodically send realistic events
setInterval(() => {
  const rand = Math.random();

  if (rand < 0.15) {
    // Attack Scenario A: Brute Force Burst (T1110.001)
    const target = Math.random() < 0.5 ? 'guest_lab' : 'admin.lab';
    const pc = COMPUTERS[Math.floor(Math.random() * COMPUTERS.length)];
    const ip = EXTERNAL_IPS[Math.floor(Math.random() * EXTERNAL_IPS.length)];
    console.log(`\n🚨 Simulating Brute Force Burst against ${target} on ${pc} from ${ip}...`);

    const burst = [];
    for (let i = 0; i < 4; i++) {
      burst.push(makeEvent(target, pc, 'FAILED', ip, '10'));
    }
    burst.push(makeEvent(target, pc, 'SUCCESS', ip, '10'));
    postEvents(burst);

  } else if (rand < 0.28) {
    // Attack Scenario B: Password Spray (T1110.003) on single PC
    const pc = 'PC-12';
    const ip = EXTERNAL_IPS[1];
    console.log(`\n🚨 Simulating Password Spraying on ${pc} from ${ip}...`);

    const spray = [
      makeEvent('stu.01', pc, 'FAILED', ip, '2'),
      makeEvent('stu.02', pc, 'FAILED', ip, '2'),
      makeEvent('stu.03', pc, 'FAILED', ip, '2'),
      makeEvent('stu.04', pc, 'FAILED', ip, '2')
    ];
    postEvents(spray);

  } else if (rand < 0.38) {
    // Scenario C: Honeytoken account probe
    const pc = COMPUTERS[Math.floor(Math.random() * COMPUTERS.length)];
    const ip = EXTERNAL_IPS[0];
    console.log(`\n🍯 Simulating Honeytoken access: admin_backup on ${pc} from ${ip}...`);
    postEvents([makeEvent('admin_backup', pc, 'FAILED', ip, '10')]);

  } else {
    // Normal routine lab activity
    const user = USERS[Math.floor(Math.random() * USERS.length)];
    const pc = COMPUTERS[Math.floor(Math.random() * COMPUTERS.length)];
    const ip = randomInternalIp();

    if (Math.random() < 0.12) {
      // Single typo then success
      postEvents([
        makeEvent(user, pc, 'FAILED', ip, '2'),
        makeEvent(user, pc, 'SUCCESS', ip, '2')
      ]);
    } else {
      postEvents([makeEvent(user, pc, 'SUCCESS', ip, '2')]);
    }
  }
}, 3000);
