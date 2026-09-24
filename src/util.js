// Shared helpers: timing, statistics, bounded concurrency, formatting, IP classification.
import crypto from 'node:crypto';
import fs from 'node:fs';

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

/**
 * Minimal .env reader. Only `KEY=VALUE` lines are honoured; a missing file is not an error.
 * Deliberately not a parser for the full dotenv grammar — quoting, exports and multi-line
 * values are out of scope, and silently accepting them would be worse than ignoring them.
 */
export function readEnvFile(file) {
  const out = {};
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    return out;
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.charAt(0) === '#') continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

/**
 * Set one key in a .env file, preserving every other line.
 *
 * Writing a bare `KEY=value` would be simpler and would silently delete whatever the user
 * already keeps there, so an existing assignment is replaced in place and anything else is
 * appended. Returns false when the file exists but cannot be read as text.
 */
export function writeEnvSetting(file, key, value) {
  let text = '';
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e && e.code !== 'ENOENT') return false;
  }
  const lines = text.length ? text.split(/\r?\n/) : [];
  const rendered = key + '=' + value;
  let replaced = false;
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(lines[i]);
    if (m && m[1] === key) {
      lines[i] = rendered;
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    if (lines.length && lines[lines.length - 1] === '') lines[lines.length - 1] = rendered;
    else lines.push(rendered);
  }
  let out = lines.join('\n');
  if (out.charAt(out.length - 1) !== '\n') out += '\n';
  try {
    fs.writeFileSync(file, out, 'utf8');
  } catch (e) {
    return false;
  }
  return true;
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

// --- terminal cell arithmetic ----------------------------------------------
//
// String#length is not a display width. Two things break naive column maths: escape
// sequences (invisible, but they occupy indices) and full-width glyphs (one code point,
// two cells). Both were silently shearing frames, so every measurement in the TUI goes
// through cellWidth() and every line is emitted through fitCell().

const ANSI_GLOBAL = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');

/** Remove SGR colour sequences, leaving the text a terminal would actually occupy. */
export function stripAnsi(s) {
  return String(s === undefined || s === null ? '' : s).replace(ANSI_GLOBAL, '');
}

// East Asian Wide and Fullwidth, plus the emoji planes: one code point, two cells.
const WIDE_RE = /[\u1100-\u115F\u2E80-\u303E\u3041-\u33FF\u3400-\u4DBF\u4E00-\u9FFF\uA000-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE10-\uFE19\uFE30-\uFE6F\uFF00-\uFF60\uFFE0-\uFFE6]|[\u{1F300}-\u{1FAFF}]|[\u{20000}-\u{2FFFD}]/u;
// Zero-width by definition: marks that attach to the preceding glyph.
const ZERO_RE = /[\u0300-\u036F\u1AB0-\u1AFF\u20D0-\u20F0\uFE00-\uFE0F\uFE20-\uFE2F\u200B-\u200F]/;

/** Display width in terminal cells, ignoring colour escapes. */
export function cellWidth(s) {
  const str = stripAnsi(s);
  let w = 0;
  for (const ch of str) {
    if (ZERO_RE.test(ch)) continue;
    w += WIDE_RE.test(ch) ? 2 : 1;
  }
  return w;
}

/** Truncate to at most n cells, appending an ellipsis only when something was dropped. */
export function clipCell(s, n) {
  const str = String(s === undefined || s === null ? '' : s);
  if (n <= 0) return '';
  if (cellWidth(str) <= n) return str;
  let out = '';
  let w = 0;
  const plain = stripAnsi(str);
  for (const ch of plain) {
    const cw = WIDE_RE.test(ch) ? 2 : ZERO_RE.test(ch) ? 0 : 1;
    if (w + cw > n - 1) break;
    out += ch;
    w += cw;
  }
  return out + '\u2026';
}

/** Pad on the right to exactly n cells (never truncates). */
export function padCell(s, n) {
  const str = String(s === undefined || s === null ? '' : s);
  const w = cellWidth(str);
  return w >= n ? str : str + ' '.repeat(n - w);
}

/** Pad on the left to exactly n cells (never truncates). */
export function padCellL(s, n) {
  const str = String(s === undefined || s === null ? '' : s);
  const w = cellWidth(str);
  return w >= n ? str : ' '.repeat(n - w) + str;
}

/** Word-wrap to at most n cells per line, breaking long words rather than overflowing. */
export function wrapCell(s, n) {
  const text = String(s === undefined || s === null ? '' : s);
  const width = Math.max(4, n);
  const lines = [];
  let line = '';
  let lw = 0;
  for (const word of text.split(/\s+/)) {
    if (!word) continue;
    if (lw === 0) {
      let w = word;
      while (cellWidth(w) > width) {
        lines.push(clipCell(w, width));
        w = stripAnsi(w).slice(clipCell(w, width - 1).length);
      }
      line = w;
      lw = cellWidth(w);
      continue;
    }
    const ww = cellWidth(word);
    if (lw + 1 + ww <= width) {
      line += ' ' + word;
      lw += 1 + ww;
    } else {
      lines.push(line);
      line = word;
      lw = ww;
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [''];
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
