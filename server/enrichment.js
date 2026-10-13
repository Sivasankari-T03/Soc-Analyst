import geoip from 'geoip-lite';

// In-memory cache for lookups to prevent rate limit starvation
const cache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Known bad actors & scanners for zero-setup offline detection
const KNOWN_THREATS = {
  '185.220.101.4': { isTor: true, score: 98, category: 'Tor Exit Node', source: 'Tor Project' },
  '185.220.101.5': { isTor: true, score: 98, category: 'Tor Exit Node', source: 'Tor Project' },
  '171.25.193.77': { isTor: true, score: 95, category: 'Tor Exit Node', source: 'Tor Project' },
  '45.155.205.9': { isScanner: true, score: 90, category: 'SSH / RDP Mass Scanner', source: 'GreyNoise' },
  '194.26.29.112': { isScanner: true, score: 85, category: 'Brute Force Botnet', source: 'AbuseIPDB' },
  '141.98.11.11': { isScanner: true, score: 92, category: 'Known Credential Stuffing', source: 'AbuseIPDB' },
  '185.180.143.10': { isScanner: true, score: 88, category: 'Internet Wide Scanner', source: 'Shodan' }
};

function getCountryFlag(countryCode) {
  if (!countryCode || countryCode === 'LOC' || countryCode === 'LAN') return '🏫';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function isPrivateIp(ip) {
  if (!ip) return true;
  const clean = ip.replace(/^::ffff:/, '').trim();
  if (clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') return true;
  
  const parts = clean.split('.').map(Number);
  if (parts.length !== 4) return false;

  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 169.254.0.0/16 (Link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;

  return false;
}

export async function enrichIp(rawIp) {
  const ip = String(rawIp || '127.0.0.1').replace(/^::ffff:/, '').trim();

  // Check cache
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  // Handle local / private lab network
  if (isPrivateIp(ip)) {
    const data = {
      ip,
      isPrivate: true,
      geo: {
        country: 'Internal Lab',
        countryCode: 'LAN',
        city: 'Local Campus LAN',
        flag: '🏫',
        lat: null,
        lon: null
      },
      reputation: {
        score: 0,
        isThreat: false,
        isTor: false,
        isScanner: false,
        category: 'Trusted Internal Network',
        provider: 'RFC 1918 Private'
      }
    };
    cache.set(ip, { data, cachedAt: Date.now() });
    return data;
  }

  // Public IP GeoIP lookup
  let geoResult = geoip.lookup(ip);
  let geo = {
    country: geoResult ? geoResult.country : 'Unknown',
    countryCode: geoResult ? geoResult.country : 'UNK',
    city: geoResult ? (geoResult.city || 'Unknown') : 'Unknown',
    flag: getCountryFlag(geoResult ? geoResult.country : 'UNK'),
    lat: geoResult && geoResult.ll ? geoResult.ll[0] : null,
    lon: geoResult && geoResult.ll ? geoResult.ll[1] : null
  };

  // Threat reputation lookup
  let rep = {
    score: 0,
    isThreat: false,
    isTor: false,
    isScanner: false,
    category: 'Clean Public IP',
    provider: 'Local GeoIP'
  };

  if (KNOWN_THREATS[ip]) {
    const t = KNOWN_THREATS[ip];
    rep = {
      score: t.score,
      isThreat: true,
      isTor: Boolean(t.isTor),
      isScanner: Boolean(t.isScanner),
      category: t.category,
      provider: t.source
    };
  } else if (process.env.ABUSEIPDB_API_KEY) {
    // Live AbuseIPDB API hook when key is configured
    try {
      const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
        headers: {
          'Key': process.env.ABUSEIPDB_API_KEY,
          'Accept': 'application/json'
        }
      });
      if (resp.ok) {
        const json = await resp.json();
        const abuseScore = json?.data?.abuseConfidenceScore || 0;
        rep = {
          score: abuseScore,
          isThreat: abuseScore >= 25,
          isTor: Boolean(json?.data?.isTor),
          isScanner: abuseScore > 50,
          category: abuseScore > 50 ? 'Reported Malicious IP' : abuseScore > 0 ? 'Suspicious' : 'Clean',
          provider: 'AbuseIPDB Live API'
        };
      }
    } catch (err) {
      // Graceful fallback to local intelligence
      console.warn(`[Enrichment] AbuseIPDB query failed for ${ip}: ${err.message}`);
    }
  }

  const enriched = {
    ip,
    isPrivate: false,
    geo,
    reputation: rep
  };

  cache.set(ip, { data: enriched, cachedAt: Date.now() });
  return enriched;
}
