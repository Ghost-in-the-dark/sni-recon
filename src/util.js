// Shared helpers: timing, statistics, bounded concurrency, formatting, IP classification.
import crypto from 'node:crypto';

export const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

export function hrMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

export function round(n, d) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return n;
  const f = Math.pow(10, d === undefined ? 2 : d);
  return Math.round(n * f) / f;
}

export function median(values) {
  const v = values
    .filter(function (x) {
      return typeof x === 'number' && Number.isFinite(x);
    })
    .slice()
    .sort(function (a, b) {
      return a - b;
    });
  if (v.length === 0) return null;
  const mid = Math.floor(v.length / 2);
  return v.length % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2;
}

export function mean(values) {
  const v = values.filter(function (x) {
    return typeof x === 'number' && Number.isFinite(x);
  });
  if (v.length === 0) return null;
  let s = 0;
  for (const x of v) s += x;
  return s / v.length;
}

export function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

// Run worker over items with at most 'limit' in flight. Worker errors are captured, never fatal.
export async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const width = Math.max(1, Math.min(limit || 4, items.length || 1));
  async function runner() {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try {
        results[i] = await worker(items[i], i);
      } catch (e) {
        results[i] = { error: errText(e) };
      }
    }
  }
  const runners = [];
  for (let i = 0; i < width; i++) runners.push(runner());
  await Promise.all(runners);
  return results;
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function isIp(s) {
  if (typeof s !== 'string') return false;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) {
    return s.split('.').every(function (o) {
      const n = Number(o);
      return n >= 0 && n <= 255 && String(n) === String(Number(o));
    });
  }
  return s.indexOf(':') !== -1 && /^[0-9a-f:.]+$/i.test(s);
}

export function familyOf(ip) {
  return ip.indexOf(':') === -1 ? 4 : 6;
}

// 198.18.0.0/15 is the benchmarking range commonly hijacked by fake-IP tun resolvers.
export function isBenchmarkIp(ip) {
  const m = /^(\d+)\.(\d+)\./.exec(ip || '');
  if (!m) return false;
  return Number(m[1]) === 198 && (Number(m[2]) === 18 || Number(m[2]) === 19);
}

export function shortFp(fp) {
  if (!fp) return '';
  return fp.replace(/:/g, '').slice(0, 16).toUpperCase();
}

export function pad(s, n) {
  let out = String(s === undefined || s === null ? '' : s);
  while (out.length < n) out += ' ';
  return out;
}

export function padL(s, n) {
  let out = String(s === undefined || s === null ? '' : s);
  while (out.length < n) out = ' ' + out;
  return out;
}

export function clip(s, n) {
  const out = String(s === undefined || s === null ? '' : s).replace(/\s+/g, ' ').trim();
  if (out.length <= n) return out;
  return out.slice(0, n - 1) + '\u2026';
}

export function pct(x) {
  if (x === null || x === undefined || !Number.isFinite(x)) return 'n/a';
  return round(x * 100, 0) + '%';
}

export function log(verbose, msg) {
  if (verbose) process.stderr.write('[sni-recon] ' + msg + '\n');
}

export function errText(e) {
  if (!e) return 'unknown error';
  if (e.code && e.message) return e.code + ': ' + e.message;
  if (e.message) return e.message;
  return String(e);
}
