// Terminal user interface.
//
// A dependency-free, in-place redrawing console UI: one frame per progress event,
// written with a cursor-home escape so the terminal never scrolls. Keys are read in raw
// mode. When stdout is not a TTY (piped, redirected, CI) the TUI degrades to plain
// line-by-line progress on stderr, and the report still goes to stdout untouched.
import readline from 'node:readline';
import { clip, pad, padL, round } from './util.js';
import { localizer, DEFAULT_LOCALE } from './i18n/index.js';
import { renderMsg } from './messages.js';

const ESC = String.fromCharCode(27);
const CSI = ESC + '[';
const HIDE_CURSOR = CSI + '?25l';
const SHOW_CURSOR = CSI + '?25h';
const HOME = CSI + 'H';
const CLEAR_DOWN = CSI + 'J';

const C = {
  reset: CSI + '0m',
  bold: CSI + '1m',
  dim: CSI + '2m',
  red: CSI + '31m',
  green: CSI + '32m',
  yellow: CSI + '33m',
  blue: CSI + '34m',
  magenta: CSI + '35m',
  cyan: CSI + '36m',
  gray: CSI + '90m',
  inv: CSI + '7m'
};

const ANSI_RE = new RegExp(ESC.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\[[0-9;]*m', 'g');

function visible(s) {
  return String(s).replace(ANSI_RE, '');
}

function width(s) {
  return visible(s).length;
}

function fit(s, n) {
  const t = clip(visible(s), n);
  return t + ' '.repeat(Math.max(0, n - t.length));
}

function padTo(s, n) {
  const len = width(s);
  return len >= n ? s : s + ' '.repeat(n - len);
}

function padToL(s, n) {
  const len = width(s);
  return len >= n ? s : ' '.repeat(n - len) + s;
}

function bar(fraction, cells, color) {
  const f = Math.max(0, Math.min(1, fraction || 0));
  const filled = Math.round(f * cells);
  const on = '\u2588'.repeat(filled);
  const off = '\u2591'.repeat(Math.max(0, cells - filled));
  return (color || C.cyan) + on + C.gray + off + C.reset;
}

function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm' + String(s % 60).padStart(2, '0') + 's';
}

function gradeColor(grade) {
  if (grade === 'excellent') return C.green;
  if (grade === 'good') return C.cyan;
  if (grade === 'fair') return C.yellow;
  return C.red;
}

// Verdict ids are machine identifiers; only the label is translated.
function gradeText(t, grade) {
  return grade ? t('grade.' + grade) : grade;
}

function certColor(c) {
  const v = c && c.verified;
  if (!v) return C.gray;
  if (v.ok) return C.green;
  if (!v.anchored) return C.red;
  return C.yellow;
}

function certLabel(c, t) {
  const v = c && c.verified;
  if (!v) return t('tui.pending');
  if (v.ok) return t('tui.genuine');
  if (!v.anchored) return t('tui.lookalike');
  return t('tui.invalid');
}

function forwardLabel(c, t) {
  const f = c && c.forward;
  if (!f || !f.attempted) return '\u2014';
  if (f.error) return t('forward.failed');
  if (f.identityMatch === true) return t('forward.identical');
  if (f.comparable) return t('forward.comparable');
  return t('forward.differs');
}

function createState(targets) {
  return {
    targets: targets || [],
    targetIndex: 0,
    target: targets && targets.length ? targets[0] : null,
    phase: 'init',
    // Either a plain string or a message value; resolved at draw time.
    phaseMessage: { key: 'tui.phase.starting' },
    discovery: { done: 0, total: 0, accepted: 0, recent: [] },
    deep: { done: 0, total: 0, current: null, items: [] },
    hoster: null,
    notes: [],
    started: Date.now(),
    finished: false,
    result: null,
    showHelp: false,
    detached: false,
    frames: 0
  };
}

/**
 * Create the UI. Returns an object with onEvent() to feed analysis progress,
 * finish() to print the closing frame, and stop() to restore the terminal.
 */
export function createTui(options) {
  const opts = options || {};
  const colour = opts.color !== false && !process.env.NO_COLOR;
  const t = typeof opts.t === 'function' ? opts.t : localizer(opts.locale || DEFAULT_LOCALE);
  const tty = opts.tty === undefined ? !!process.stdout.isTTY : !!opts.tty;
  const state = createState(opts.targets);
  let stopped = false;
  let keyHandler = null;
  let resizeHandler = null;

  if (!colour) {
    for (const k of Object.keys(C)) C[k] = '';
  }

  function columns() {
    return Math.max(60, Math.min((process.stdout.columns || 100) - 1, 160));
  }

  function renderBox(lines, w) {
    const out = [];
    out.push(C.gray + '\u250c' + '\u2500'.repeat(w - 2) + '\u2510' + C.reset);
    for (const line of lines) {
      const content = padTo(line, w - 4);
      out.push(C.gray + '\u2502' + C.reset + ' ' + content + ' ' + C.gray + '\u2502' + C.reset);
    }
    out.push(C.gray + '\u2514' + '\u2500'.repeat(w - 2) + '\u2518' + C.reset);
    return out;
  }

  function headerLines(w) {
    const s = state;
    const lines = [];
    const t = s.target || {};
    const title = C.bold + C.cyan + 'sni-recon' + C.reset + C.gray + ' \u00b7 ' + t('tui.title') + C.reset;
    const elapsed = C.gray + fmtDuration(Date.now() - s.started) + C.reset;
    const left = title;
    const right = elapsed;
    lines.push(left + ' '.repeat(Math.max(1, w - 4 - width(left) - width(right))) + right);
    let targetLine = C.bold + (t.address || '?') + C.reset + ':' + (t.port || 443);
    if (s.targets.length > 1) {
      targetLine += C.gray + '  [' + (s.targetIndex + 1) + '/' + s.targets.length + ']' + C.reset;
    }
    lines.push(C.gray + pad(t('tui.target'), 9) + C.reset + targetLine);
    if (s.hoster && s.hoster.ok) {
      const bits = [s.hoster.asn, s.hoster.asName || s.hoster.org].filter(Boolean).join(' ');
      const place = s.hoster.city ? s.hoster.city + ', ' + (s.hoster.countryCode || '') : s.hoster.country || '';
      let line = C.gray + pad(t('tui.operator'), 9) + C.reset + C.magenta + clip(bits, 40) + C.reset;
      if (place) line += C.gray + ' \u00b7 ' + clip(place, 22) + C.reset;
      line += s.hoster.hosting
        ? C.yellow + '  [' + t('tui.datacenter') + ']' + C.reset
        : C.green + '  [' + t('tui.notDatacenter') + ']' + C.reset;
      lines.push(line);
    }
    lines.push(C.gray + pad(t('tui.phase'), 9) + C.reset + C.bold + renderMsg(t, s.phaseMessage) + C.reset);
    return lines;
  }

  function progressLines(w) {
    const s = state;
    const out = [];
    const inner = w - 4;
    if (s.phase === 'discovery' || s.phase === 'controls' || s.phase === 'init') {
      const d = s.discovery;
      const frac = d.total ? d.done / d.total : 0;
      const label =
        C.gray + pad(t('tui.whitelist'), 11) + C.reset + bar(frac, 40) + '  ' +
        d.done + '/' + d.total + ' ' + t('tui.probed') + ', ' + C.green + d.accepted + C.reset + ' ' + t('tui.accepted');
      out.push(label);
    }
    if (s.phase === 'deep') {
      const d = s.deep;
      const frac = d.total ? d.done / d.total : 0;
      out.push(
        C.gray + pad(t('tui.deep'), 11) + C.reset + bar(frac, 40, C.green) + '  ' + d.done + '/' + d.total +
          (d.current ? C.gray + '  ' + clip(d.current, 28) + C.reset : '')
      );
    }
    return out;
  }

  function tableLines(w) {
    const s = state;
    const out = [];
    const cols = { name: 27, presented: 26, cert: 12, fwd: 12, score: 6, ms: 6 };
    if (s.deep.items.length) {
      // Two distinct things matter: the name being tested, and the identity the node
      // actually presents for it. On a catch-all host those differ on every row.
      out.push(
        C.gray +
          '  ' +
          padTo(t('tui.candidate'), cols.name) +
          padTo(t('tui.presentedAs'), cols.presented) +
          padTo(t('tui.certificate'), cols.cert) +
          padTo(t('tui.forward'), cols.fwd) +
          padToL(t('tui.score'), cols.score) +
          padToL(t('tui.ms'), cols.ms) +
          C.reset
      );
      const shown = s.deep.items.slice(-12);
      for (const c of shown) {
        const leaf = c.leaf;
        const presented = leaf && leaf.cn ? leaf.cn : '\u2014';
        const same = String(presented).toLowerCase() === String(c.name).toLowerCase();
        const certTxt = certLabel(c, t);
        const fwd = forwardLabel(c, t);
        const fwdColour =
          fwd === t('forward.identical') ? C.green
          : fwd === t('forward.comparable') ? C.cyan
          : fwd === t('forward.failed') || fwd === t('forward.differs') ? C.red
          : C.gray;
        out.push(
          '  ' +
            C.bold + padTo(clip(c.name, cols.name - 1), cols.name) + C.reset +
            (same ? C.gray : C.magenta) + padTo(clip(presented, cols.presented - 1), cols.presented) + C.reset +
            certColor(c) + padTo(certTxt, cols.cert) + C.reset +
            fwdColour + padTo(fwd, cols.fwd) + C.reset +
            padToL(c.score == null ? '' : String(c.score), cols.score) +
            padToL(c.stability && c.stability.latencyMs ? String(round(c.stability.latencyMs.median, 0)) : '', cols.ms)
        );
      }
      if (s.deep.items.length > shown.length) {
        out.push(C.gray + '  \u2026 ' + t('tui.earlier', { n: s.deep.items.length - shown.length }) + C.reset);
      }
    } else if (s.discovery.recent.length) {
      out.push(C.gray + t('tui.recent') + C.reset);
      const shown = s.discovery.recent.slice(-8);
      for (const r of shown) {
        const mark = r.accepted ? C.green + '\u2713' + C.reset : C.gray + '\u00b7' + C.reset;
        out.push(
          '  ' + mark + ' ' + pad(clip(r.name, 40), 42) +
            (r.accepted ? C.green + t('identity.accepted') + C.reset : C.gray + t('identity.rejected') + C.reset)
        );
      }
    } else {
      out.push(C.gray + t('tui.waiting') + C.reset);
    }
    return out;
  }

  function footerLines(w) {
    const s = state;
    const out = [];
    if (s.finished && s.result) {
      const r = s.result;
      if (r.summary && r.summary.notes) {
        for (const note of r.summary.notes.slice(0, 2)) {
          out.push(C.gray + pad(t('tui.note'), 6) + C.reset + clip(renderMsg(t, note), w - 10));
        }
      }
      out.push('');
      if (r.masking) {
        const m = r.masking;
        const tag = m.masking
          ? C.red + C.bold + '[!] ' + t('masking.detected') + C.reset
          : m.verdict === 'genuine-front'
          ? C.green + C.bold + '[ok] ' + t('masking.notDetected') + C.reset
          : C.yellow + C.bold + '[?] ' + t('masking.inconclusive') + C.reset;
        out.push(tag + C.gray + '  ' + t('method.' + m.method) + ' \u00b7 ' + t('masking.confidence') + ' ' + t('confidence.' + m.confidence) + C.reset);
      }
      if (r.best) {
        out.push(
          C.bold + t('tui.recommended') + '  ' + C.green + r.best.name + C.reset +
            C.gray + '   ' + r.best.score + '/100 ' + gradeText(t, r.best.grade) + C.reset
        );
        out.push(C.gray + '  "serverNames": ["' + r.best.name + '"], "dest": "' + r.best.dest + '"' + C.reset);
      } else {
        out.push(C.yellow + t('tui.noName') + C.reset);
      }
    }
    out.push('');
    out.push(C.gray + (s.finished ? t('tui.quit') : t('tui.detachHint')) + C.reset);
    return out;
  }

  function frame() {
    if (stopped || state.detached) return;
    const w = columns();
    const lines = [];
    const hdr = headerLines(w);
    lines.push(C.gray + '\u250c' + ' \u2500 sni-recon ' + '\u2500'.repeat(Math.max(0, w - 18)) + '\u2510' + C.reset);
    for (let i = 0; i < hdr.length; i++) {
      const isTitle = i === 0;
      const content = isTitle ? padTo(hdr[i], w - 4) : padTo(' ' + hdr[i], w - 4);
      lines.push(C.gray + '\u2502' + C.reset + ' ' + content + ' ' + C.gray + '\u2502' + C.reset);
    }
    lines.push(C.gray + '\u2514' + '\u2500'.repeat(w - 2) + '\u2518' + C.reset);
    lines.push('');
    for (const l of progressLines(w)) lines.push(' ' + l);
    lines.push('');
    for (const l of tableLines(w)) lines.push(' ' + l);
    lines.push('');
    for (const l of footerLines(w)) lines.push(' ' + l);

    let out = HOME;
    const total = (process.stdout.rows || 40);
    const shown = lines.slice(0, total - 1);
    out += shown.map(function (l) { return padTo(l, w) + '\n'; }).join('');
    out += CLEAR_DOWN;
    process.stdout.write(out);
    state.frames++;
  }

  function plainEvent(evt) {
    if (evt.type === 'phase') process.stderr.write('[sni-recon] ' + renderMsg(t, evt.message) + '\n');
    else if (evt.type === 'discovery' && (evt.done === evt.total || evt.done % 25 === 0)) {
      process.stderr.write('[sni-recon] ' + t('progress.discoveryShort', { done: evt.done, total: evt.total }) + '\n');
    } else if (evt.type === 'deep-done') {
      process.stderr.write('[sni-recon] ' + t('progress.deepShort', { index: evt.index, total: evt.total, name: evt.name }) + '\n');
    } else if (evt.type === 'unreachable') {
      process.stderr.write('[sni-recon] ' + t('progress.unreachableShort', { message: renderMsg(t, evt.message) }) + '\n');
    }
  }

  function onEvent(evt) {
    if (!evt) return;
    if (!tty) {
      plainEvent(evt);
      return;
    }
    switch (evt.type) {
      case 'phase':
        state.phase = evt.phase || state.phase;
        state.phaseMessage = evt.message || state.phaseMessage; // message value, rendered at draw time
        if (evt.total && evt.phase === 'discovery') state.discovery.total = evt.total;
        if (evt.total && evt.phase === 'deep') state.deep.total = evt.total;
        break;
      case 'discovery':
        state.discovery.done = evt.done;
        state.discovery.total = evt.total;
        if (evt.accepted) state.discovery.accepted++;
        state.discovery.recent.push({ name: evt.name, accepted: !!evt.accepted });
        if (state.discovery.recent.length > 20) state.discovery.recent.shift();
        break;
      case 'deep-start':
        state.deep.current = evt.name;
        if (evt.total) state.deep.total = evt.total;
        break;
      case 'deep-done':
        // The candidate object itself arrives in a following 'candidate' event; this
        // one only advances the progress counter.
        state.deep.done = evt.index;
        if (evt.total) state.deep.total = evt.total;
        state.deep.current = null;
        break;
      case 'unreachable':
        state.notes.push(evt.message);
        break;
      default:
        break;
    }
    frame();
  }

  /** Feed a fully analysed candidate so the table can show certificates and scores. */
  let lastCandidate = null;
  function addCandidate(c) {
    if (!c || c === lastCandidate) return;
    lastCandidate = c;
    state.deep.items.push(c);
    if (tty) frame();
  }

  function setHoster(h) {
    state.hoster = h;
    if (tty) frame();
  }

  function setTarget(t, index) {
    state.target = t;
    if (index !== undefined) state.targetIndex = index;
    state.phase = 'init';
    state.phaseMessage = { key: 'tui.phase.starting' };
    state.discovery = { done: 0, total: 0, accepted: 0, recent: [] };
    state.deep = { done: 0, total: 0, current: null, items: [] };
    state.hoster = null;
    state.finished = false;
    state.result = null;
    state.started = Date.now();
    if (tty) frame();
  }

  function finish(result) {
    state.result = result;
    state.finished = true;
    state.phase = 'done';
    state.phaseMessage = { key: 'tui.phase.complete' };
    if (tty) {
      frame();
      // leave the finished frame on screen; the report follows below it
      process.stdout.write(SHOW_CURSOR + '\n');
      stopped = true;
      cleanup();
    }
  }

  function cleanup() {
    if (keyHandler && process.stdin.isTTY) {
      process.stdin.removeListener('keypress', keyHandler);
      try {
        if (process.stdin.setRawMode) process.stdin.setRawMode(false);
      } catch (e) { /* ignore */ }
      process.stdin.pause();
      keyHandler = null;
    }
    if (resizeHandler) {
      process.stdout.removeListener('resize', resizeHandler);
      resizeHandler = null;
    }
    if (tty) process.stdout.write(SHOW_CURSOR);
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    cleanup();
  }

  function start() {
    if (!tty) {
      process.stderr.write('[sni-recon] ' + t('progress.scanning') + '\n');
      return;
    }
    process.stdout.write(HIDE_CURSOR);
    readline.emitKeypressEvents(process.stdin);
    if (process.stdin.isTTY) {
      try {
        process.stdin.setRawMode(true);
      } catch (e) { /* ignore */ }
      process.stdin.resume();
    }
    keyHandler = function (str, key) {
      if (!key) return;
      if (key.ctrl && key.name === 'c') {
        stop();
        process.stdout.write('\n');
        process.kill(process.pid, 'SIGINT');
        return;
      }
      if (key.name === 'q' || key.name === 'escape') {
        state.detached = true;
        process.stdout.write(CLEAR_DOWN + SHOW_CURSOR);
        process.stderr.write('[sni-recon] ' + t('progress.detached') + '\n');
        stop();
      }
    };
    process.stdin.on('keypress', keyHandler);
    resizeHandler = function () {
      frame();
    };
    process.stdout.on('resize', resizeHandler);
    frame();
  }

  return {
    tty: tty,
    t: t,
    start: start,
    stop: stop,
    finish: finish,
    onEvent: onEvent,
    addCandidate: addCandidate,
    setHoster: setHoster,
    setTarget: setTarget,
    state: state
  };
}

/** One-line, colour-free progress renderer for logs and CI. */
export function createPlainProgress(stream) {
  const out = stream || process.stderr;
  let last = '';
  return function (evt) {
    let line = null;
    if (evt.type === 'discovery') line = 'discovery ' + evt.done + '/' + evt.total;
    else if (evt.type === 'deep-done') line = 'deep ' + evt.index + '/' + evt.total + ' ' + evt.name;
    else if (evt.type === 'phase') line = evt.message;
    if (line && line !== last) {
      out.write('[sni-recon] ' + line + '\n');
      last = line;
    }
  };
}
