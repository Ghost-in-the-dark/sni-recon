// Hosting-provider identification.
//
// Knowing *who runs the box* is what turns "a certificate came back" into a judgement
// about whether a domain's identity is being used by someone else. Two free, keyless
// sources are used: ip-api.com (rich, includes a hosting flag) and RDAP (authoritative
// registry data). Both are optional — if neither answers, detection degrades to
// heuristics over TLS/HTTP signals instead of failing.
import https from 'node:https';
import http from 'node:http';
import { UA, errText, isIp, log } from './util.js';
import { REDACTED } from './redact.js';

const CACHE = new Map();

const HOSTING_HINTS = [
  'hosting',
  'host',
  'vps',
  'vds',
  'cloud',
  'server',
  'datacenter',
  'data center',
  'colocation',
  'colo',
  'dedicated',
  'vpn',
  'proxy',
  'network',
  'telecom',
  'communications',
  'internet',
  'digital',
  'technologies',
  'solutions',
  'systems',
  'ltd',
  'llc',
  'gmbh',
  's.r.o',
  'b.v',
  'oy',
  'ab',
  'sarl',
  'sas'
];

function getText(url, opts) {
  const options = opts || {};
  const timeout = options.timeout || 7000;
  const maxHops = options.maxHops == null ? 3 : options.maxHops;
  const rejectUnauthorized = options.rejectUnauthorized !== false;
  let current = url;
  let hops = 0;
  return new Promise(function (resolve) {
    function attempt() {
      const u = new URL(current);
      const mod = u.protocol === 'http:' ? http : https;
      const req = mod.get(
        current,
        {
          timeout: timeout,
          rejectUnauthorized: rejectUnauthorized,
          headers: { 'user-agent': options.userAgent || UA, accept: options.accept || 'application/json' }
        },
        function (res) {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && hops < maxHops) {
            hops++;
            res.resume();
            current = new URL(res.headers.location, current).toString();
            attempt();
            return;
          }
          let data = '';
          res.setEncoding('utf8');
          res.on('data', function (c) {
            data += c;
            if (data.length > 1 << 20) req.destroy();
          });
          res.on('end', function () {
            resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: data });
          });
        }
      );
      req.on('timeout', function () {
        req.destroy();
        resolve({ ok: false, error: 'timeout' });
      });
      req.on('error', function (e) {
        resolve({ ok: false, error: errText(e) });
      });
    }
    try {
      attempt();
    } catch (e) {
      resolve({ ok: false, error: errText(e) });
    }
  });
}

function looksLikeHoster(org) {
  const s = String(org || '').toLowerCase();
  if (!s) return null;
  for (const h of HOSTING_HINTS) {
    if (s.indexOf(h) !== -1) return true;
  }
  return false;
}

export async function lookupIpApi(ip, opts) {
  const fields =
    'status,message,continent,country,countryCode,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting';
  const url = 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=' + fields;
  const r = await getText(url, { timeout: (opts && opts.timeout) || 6000 });
  if (!r.ok) return { source: 'ip-api', ok: false, error: r.error || 'HTTP ' + r.status };
  let j;
  try {
    j = JSON.parse(r.body);
  } catch (e) {
    return { source: 'ip-api', ok: false, error: 'invalid JSON' };
  }
  if (j.status !== 'success') return { source: 'ip-api', ok: false, error: j.message || 'lookup failed' };
  const asn = j.as ? String(j.as).split(' ')[0] : null;
  return {
    source: 'ip-api',
    ok: true,
    ip: ip,
    country: j.country || null,
    countryCode: j.countryCode || null,
    city: j.city || null,
    region: j.regionName || null,
    isp: j.isp || null,
    org: j.org || null,
    asn: asn,
    asName: j.as ? String(j.as).replace(/^\S+\s+/, '') : j.asname || null,
    ptr: j.reverse || null,
    hosting: typeof j.hosting === 'boolean' ? j.hosting : looksLikeHoster(j.isp || j.org),
    proxy: typeof j.proxy === 'boolean' ? j.proxy : null,
    mobile: typeof j.mobile === 'boolean' ? j.mobile : null
  };
}

export async function lookupRdap(ip, opts) {
  const url = 'https://rdap.org/ip/' + encodeURIComponent(ip);
  const r = await getText(url, { timeout: (opts && opts.timeout) || 7000, maxHops: 4 });
  if (!r.ok) return { source: 'rdap', ok: false, error: r.error || 'HTTP ' + r.status };
  let j;
  try {
    j = JSON.parse(r.body);
  } catch (e) {
    return { source: 'rdap', ok: false, error: 'invalid JSON' };
  }
  const entities = [];
  for (const e of j.entities || []) {
    const name = (e.vcardArray && e.vcardArray[1] || []).find(function (row) {
      return row[0] === 'fn';
    });
    if (name) entities.push(name[3]);
    if (e.handle && entities.indexOf(e.handle) === -1 && /^(ORG|AS)/i.test(e.handle)) entities.push(e.handle);
  }
  const org = entities.find(function (x) {
    return !/^AS\d+$/.test(x);
  });
  return {
    source: 'rdap',
    ok: true,
    ip: ip,
    handle: j.handle || null,
    name: j.name || null,
    type: j.type || null,
    country: j.country || null,
    startAddress: j.startAddress || null,
    endAddress: j.endAddress || null,
    org: org || j.name || null,
    entities: entities
  };
}

/** Look up one address across all sources. Never throws; returns partial data on failure. */
export async function lookupHoster(ip, opts) {
  const options = opts || {};
  const enable = options.enable === false ? false : true;
  if (!enable || !isIp(ip)) {
    return { ip: ip, ok: false, skipped: !enable, error: enable ? 'not an IP literal' : 'lookups disabled' };
  }
  if (options.cache !== false && CACHE.has(ip)) return CACHE.get(ip);
  log(options.verbose, 'hoster lookup ' + ip);
  const out = { ip: ip, ok: false, sources: {}, warnings: [] };
  const results = await Promise.all([
    lookupIpApi(ip, options).catch(function (e) {
      return { source: 'ip-api', ok: false, error: errText(e) };
    }),
    lookupRdap(ip, options).catch(function (e) {
      return { source: 'rdap', ok: false, error: errText(e) };
    })
  ]);
  for (const r of results) {
    out.sources[r.source] = r;
    if (!r.ok) out.warnings.push(r.source + ': ' + (r.error || 'failed'));
  }
  const api = out.sources['ip-api'];
  const rdap = out.sources.rdap;
  out.ok = !!(api && api.ok) || !!(rdap && rdap.ok);
  const primary = api && api.ok ? api : null;
  out.asn = primary ? primary.asn : null;
  out.asName = primary ? primary.asName : null;
  out.isp = primary ? primary.isp : null;
  out.org = (primary && primary.org) || (rdap && rdap.org) || null;
  out.country = (primary && primary.country) || (rdap && rdap.country) || null;
  out.countryCode = primary ? primary.countryCode : null;
  out.city = primary ? primary.city : null;
  out.ptr = primary ? primary.ptr : null;
  out.hosting = primary ? primary.hosting : looksLikeHoster(out.org);
  out.proxy = primary ? primary.proxy : null;
  if (out.hosting === null && out.org) out.hosting = looksLikeHoster(out.org);
  if (options.cache !== false) CACHE.set(ip, out);
  return out;
}

/** True when the two addresses are run by the same organisation or ASN. */
export function sameOperator(a, b) {
  if (!a || !b || !a.ok || !b.ok) return null;
  if (a.asn && b.asn && a.asn === b.asn) return true;
  if (a.org && b.org) {
    const na = a.org.toLowerCase().replace(/[^a-z0-9]/g, '');
    const nb = b.org.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (na && nb && (na === nb || na.indexOf(nb) !== -1 || nb.indexOf(na) !== -1)) return true;
  }
  return false;
}

export function clearHosterCache() {
  CACHE.clear();
}

export function describeHoster(h) {
  if (!h || typeof h !== 'object') return 'unknown';
  // A fully redacted record would otherwise render as "[redacted] [redacted] · [redacted],
  // [redacted]" — technically correct and useless to read.
  if (h.asn === REDACTED || h.org === REDACTED || h.isp === REDACTED) {
    const present = ['asn', 'asName', 'org', 'isp', 'city', 'countryCode', 'country'].filter(function (k) {
      return h[k] !== undefined && h[k] !== null;
    });
    if (present.length && present.every(function (k) { return h[k] === REDACTED; })) return REDACTED;
  }
  const bits = [];
  if (h.asn) bits.push(h.asn + (h.asName ? ' ' + h.asName : ''));
  else if (h.org) bits.push(h.org);
  else if (h.isp) bits.push(h.isp);
  if (h.city || h.countryCode) bits.push([h.city, h.countryCode].filter(Boolean).join(', '));
  if (bits.length) return bits.join(' \u00b7 ');
  // A redacted or degraded record still has a label worth showing; only a record with
  // no identity left at all is reported as unknown.
  if (h.label) return String(h.label);
  return 'unknown';
}
