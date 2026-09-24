// Name resolution with DNS-over-HTTPS, plus detection of fake-IP hijacking.
import { promises as dnsp } from 'node:dns';
import https from 'node:https';
import { isIp, errText, isBenchmarkIp, UA } from './util.js';

const CACHE = new Map();

const DOH_PROVIDERS = [
  { id: 'cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { id: 'google', url: 'https://dns.google/resolve' }
];

function dohRequest(url, timeoutMs) {
  return new Promise(function (resolve, reject) {
    let req;
    try {
      req = https.get(
        url,
        { headers: { accept: 'application/dns-json', 'user-agent': UA }, timeout: timeoutMs },
        function (res) {
          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error('DoH HTTP ' + res.statusCode));
            return;
          }
          let data = '';
          res.setEncoding('utf8');
          res.on('data', function (c) {
            data += c;
            if (data.length > 1 << 20) req.destroy(new Error('DoH response too large'));
          });
          res.on('end', function () {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        }
      );
    } catch (e) {
      reject(e);
      return;
    }
    req.on('timeout', function () {
      req.destroy(new Error('DoH timeout'));
    });
    req.on('error', reject);
  });
}

function answersToIps(json, type) {
  const out = [];
  const list = (json && json.Answer) || [];
  for (const a of list) {
    if (type === 'A' && a.type !== 1) continue;
    if (type === 'AAAA' && a.type !== 28) continue;
    const v = String(a.data || '').trim();
    if (isIp(v)) out.push(v);
  }
  return out;
}

export async function dohResolve(host, timeoutMs) {
  const errors = [];
  for (const p of DOH_PROVIDERS) {
    for (const type of ['A', 'AAAA']) {
      const url = p.url + '?name=' + encodeURIComponent(host) + '&type=' + type;
      try {
        const json = await dohRequest(url, timeoutMs || 6000);
        const ips = answersToIps(json, type);
        if (ips.length) return { provider: p.id, type: type, addresses: ips, errors: errors };
      } catch (e) {
        errors.push(p.id + '/' + type + ': ' + errText(e));
      }
    }
  }
  return { provider: null, type: null, addresses: [], errors: errors };
}

export async function systemResolve(host) {
  const out = [];
  const errors = [];
  try {
    const v4 = await dnsp.resolve4(host);
    for (const ip of v4) out.push(ip);
  } catch (e) {
    errors.push('A: ' + errText(e));
  }
  if (!out.length) {
    try {
      const v6 = await dnsp.resolve6(host);
      for (const ip of v6) out.push(ip);
    } catch (e) {
      errors.push('AAAA: ' + errText(e));
    }
  }
  return { addresses: out, errors: errors };
}

// Resolve with DoH first (immune to local fake-IP hijacking), system DNS as fallback.
export async function resolveHost(host, opts) {
  const options = opts || {};
  const key = host + '|' + (options.doh === false ? 'sys' : 'doh');
  if (options.cache !== false && CACHE.has(key)) return CACHE.get(key);
  const result = {
    host: host,
    source: null,
    addresses: [],
    errors: [],
    fakeIp: false
  };
  if (isIp(host)) {
    result.addresses = [host];
    result.source = 'literal';
    CACHE.set(key, result);
    return result;
  }
  if (options.doh !== false) {
    const d = await dohResolve(host, options.timeout);
    result.errors = result.errors.concat(d.errors);
    if (d.addresses.length) {
      result.addresses = d.addresses;
      result.source = 'doh:' + d.provider;
    }
  }
  if (!result.addresses.length) {
    const s = await systemResolve(host);
    result.errors = result.errors.concat(s.errors);
    if (s.addresses.length) {
      result.addresses = s.addresses;
      result.source = result.source ? result.source + '+system' : 'system';
    }
  }
  result.fakeIp = result.addresses.some(function (ip) {
    return isBenchmarkIp(ip);
  });
  if (options.cache !== false) CACHE.set(key, result);
  return result;
}

export function clearCache() {
  CACHE.clear();
}

// Pick a usable address, preferring non-hijacked IPv4 that is not the node under test.
export function pickAddress(res, exclude) {
  const skip = new Set(exclude || []);
  const v4 = res.addresses.filter(function (ip) {
    return ip.indexOf(':') === -1 && !skip.has(ip);
  });
  const clean = v4.filter(function (ip) {
    return !isBenchmarkIp(ip);
  });
  if (clean.length) return clean[0];
  const v6 = res.addresses.filter(function (ip) {
    return ip.indexOf(':') !== -1 && !skip.has(ip);
  });
  if (v6.length) return v6[0];
  if (v4.length) return v4[0];
  return null;
}
