// Terminal user interface.
//
// A dependency-free, in-place redrawing console UI: one frame per progress event,
// written with a cursor-home escape so the terminal never scrolls. Keys are read in raw
// mode. When stdout is not a TTY (piped, redirected, CI) the TUI degrades to plain
// line-by-line progress on stderr, and the report still goes to stdout untouched.
import readline from 'node:readline';
import { clip, pad, round } from './util.js';
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

function padTo(s, n) {
  const len = width(s);
  return len >= n ? s : s + ' '.repeat(n - len);
}

function padToL(s, n) {
  const len = width(s);
  return len >= n ? s : ' '.repeat(n - len) + s;
}

const ANSI_STICKY = new RegExp(ANSI_RE.source, 'y');

/**
 * Fit a coloured string into exactly n cells: pad when short, truncate when long.
 *
 * clip() cannot be used here because it strips ANSI, so an over-long line would silently
 * lose its colour — and an un-truncated line is worse than cosmetic damage: it wraps, and
 * every later line of the frame lands one row lower than the cursor arithmetic assumes.
 */
function fitTo(s, n) {
  const str = String(s === undefined || s === null ? '' : s);
  const plain = width(str);
  if (plain <= n) return str + ' '.repeat(n - plain);
  const limit = Math.max(0, n - 1);
  let out = '';
  let shown = 0;
  let i = 0;
  while (i < str.length && shown < limit) {
    ANSI_STICKY.lastIndex = i;
    const m = ANSI_STICKY.exec(str);
    if (m) {
      out += m[0];
      i = ANSI_STICKY.lastIndex;
      continue;
    }
    out += str[i];
    shown++;
    i++;
  }
  // The reset matters: truncation can land inside a coloured run, and the frame is written
  // as one buffer, so an unclosed colour would bleed into every following line.
  return out + C.reset + '\u2026' + ' '.repeat(Math.max(0, n - shown - 1));
}

/** Pad or truncate to exactly n cells. Every frame line goes through this. */
function frameCell(s, n) {
  const str = String(s === undefined || s === null ? '' : s);
  const plain = width(str);
  if (plain <= n) return str + ' '.repeat(n - plain) + C.reset;
  return fitTo(str, n);
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

  // One column for every field label, so the values line up instead of drifting with the
  // word length of whatever language is active. The width comes from the longest label in
  // the active locale — a fixed 10 clipped Russian "примечание" into "примечани…".
  const LABEL_KEYS = ['tui.target', 'tui.operator', 'tui.phase', 'tui.note'];
  const LABEL = LABEL_KEYS.reduce(function (max, key) {
    return Math.max(max, width(t(key)));
  }, 0) + 2;

  function field(key, value) {
    return C.gray + pad(clip(t(key), LABEL - 1), LABEL) + C.reset + value;
  }

  function rightAlign(left, right, inner) {
    return left + ' '.repeat(Math.max(1, inner - width(left) - width(right))) + right;
  }

  function titleLine(w) {
    const brand = C.bold + C.cyan + 'sni-recon' + C.reset;
    const room = Math.max(10, w - 4 - width(brand) - 3);
    return brand + C.gray + ' \u00b7 ' + C.reset + C.gray + clip(t('tui.title'), room) + C.reset;
  }

  /** Box-drawing frame: top border bearing the title, content rows, bottom border. */
  function boxLines(title, rows, w) {
    const inner = w - 4;
    const fill = '\u2500'.repeat(Math.max(0, inner - width(title) - 1));
    const out = [C.gray + '\u250c' + C.reset + ' ' + title + ' ' + C.gray + fill + '\u2510' + C.reset];
    for (const row of rows) {
      out.push(C.gray + '\u2502' + C.reset + ' ' + fitTo(row, inner) + ' ' + C.gray + '\u2502' + C.reset);
    }
    out.push(C.gray + '\u2514' + '\u2500'.repeat(w - 2) + '\u2518' + C.reset);
    return out;
  }

  /** Header rows. The elapsed clock rides the target row so the title row stays clean. */
  function headerLines(w) {
    const s = state;
    const inner = w - 4;
    const rows = [];
    // NOT `t`: that name is bound to the translator for the whole factory. Shadowing it
    // here made every redraw throw "t is not a function", which the non-TTY path never hit
    // because it never renders a frame.
    const target = s.target || {};
    const elapsed = C.gray + fmtDuration(Date.now() - s.started) + C.reset;

    let targetLine = C.bold + (target.address || '?') + C.reset + ':' + (target.port || 443);
    if (s.targets.length > 1) {
      targetLine += C.gray + ' [' + (s.targetIndex + 1) + '/' + s.targets.length + ']' + C.reset;
    }
    rows.push(rightAlign(field('tui.target', targetLine), elapsed, inner));

    if (s.hoster && s.hoster.ok) {
      const bits = [s.hoster.asn, s.hoster.asName || s.hoster.org].filter(Boolean).join(' ');
      const place = s.hoster.city ? s.hoster.city + ', ' + (s.hoster.countryCode || '') : s.hoster.country || '';
      let line = C.magenta + clip(bits, 42) + C.reset;
      if (place) line += C.gray + ' \u00b7 ' + clip(place, 20) + C.reset;
      line += s.hoster.hosting
        ? C.yellow + '  [' + t('tui.datacenter') + ']' + C.reset
        : C.green + '  [' + t('tui.notDatacenter') + ']' + C.reset;
      rows.push(field('tui.operator', line));
    }

    rows.push(field('tui.phase', C.bold + renderMsg(t, s.phaseMessage) + C.reset));
    return rows;
  }

  const BAR_MAX = 44;
  const BAR_MIN = 10;

  /**
   * The bar absorbs the width left over after the text that shares its line — measured, not
   * guessed, so the Russian counters (longer than the English ones) do not push the line
   * past the terminal and make it wrap.
   */
  function barCells(w, tail) {
    return Math.max(BAR_MIN, Math.min(BAR_MAX, w - 4 - 11 - 2 - tail));
  }

  function progressLines(w) {
    const s = state;
    const out = [];
    if (s.phase === 'discovery' || s.phase === 'controls' || s.phase === 'init') {
      const d = s.discovery;
      const frac = d.total ? d.done / d.total : 0;
      const counts = d.done + '/' + d.total + ' ' + t('tui.probed') + ', ' +
        C.green + d.accepted + C.reset + ' ' + t('tui.accepted');
      out.push(
        C.gray + pad(clip(t('tui.whitelist'), 10), 11) + C.reset + bar(frac, barCells(w, width(counts))) + '  ' + counts
      );
    }
    if (s.phase === 'deep') {
      const d = s.deep;
      const frac = d.total ? d.done / d.total : 0;
      const current = d.current ? C.gray + '  ' + clip(d.current, 30) + C.reset : '';
      const counts = d.done + '/' + d.total + current;
      out.push(
        C.gray + pad(clip(t('tui.deep'), 10), 11) + C.reset + bar(frac, barCells(w, width(counts))) + '  ' + counts
      );
    }
    return out;
  }

  // Row count is a budget, not a constant: a short terminal must still show the newest
  // candidates rather than filling the screen with older ones and scrolling the header off.
  const TABLE_ROWS_MAX = 12;

  /**
   * How many candidate rows fit.
   *
   * `reserved` is every line of the frame that is not a candidate row, counted by frame()
   * before the table is built. When the list is longer than the budget an extra line is
   * spent on the "earlier candidates" marker, so the budget shrinks by one more — otherwise
   * that marker is what pushes the last line of the frame off the screen.
   */
  function rowBudget(reserved, total) {
    const available = (process.stdout.rows || 40) - 1;
    let rows = Math.max(3, Math.min(TABLE_ROWS_MAX, available - reserved - 1));
    if (total > rows) rows = Math.max(3, Math.min(TABLE_ROWS_MAX, available - reserved - 2));
    return rows;
  }

  // Below this width the four right-hand columns cannot share a line with a readable name,
  // so the table drops to the names plus their verdict and says so in the header.
  const COMPACT_BELOW = 78;

  function tableLines(w, reserved) {
    const s = state;
    const out = [];
    const rows = rowBudget(reserved, s.deep.items.length);

    if (s.deep.items.length) {
      if (w < COMPACT_BELOW) {
        // Two things again, but stacked in one cell: the name, then what the node actually
        // presented for it and how good that is.
        const mark = 4;
        const nameW = Math.max(12, Math.floor((w - 4 - mark) / 2));
        out.push(
          C.gray + '  ' +
            padTo(t('tui.candidate'), nameW) +
            padTo(t('tui.presentedAs'), nameW) +
            C.reset
        );
        const shown = s.deep.items.slice(-rows);
        for (const c of shown) {
          const leaf = c.leaf;
          const presentedName = leaf && leaf.cn ? leaf.cn : '\u2014';
          const same = String(presentedName).toLowerCase() === String(c.name).toLowerCase();
          // The verdict is appended only as far as it fits: on a narrow terminal the two
          // halves plus a full verdict do not fit on one line, and half a verdict reads as
          // a wrong answer rather than a truncated one.
          const certTxt = certLabel(c, t);
          // Sized against what is left after the presented name, not against the whole cell.
          // Fitting the verdict to the cell alone is how "genuine · identical" turned into
          // "genuine · …" — a truncated verdict reads as a different answer.
          const room = nameW - 1 - width(presentedName) - 2;
          let verdict = certTxt + ' \u00b7 ' + forwardLabel(c, t);
          if (width(verdict) > room) verdict = certTxt;
          if (width(verdict) > room) verdict = '';
          out.push(
            '  ' +
              C.bold + padTo(clip(c.name, nameW - 1), nameW) + C.reset +
              (same ? C.gray : C.magenta) +
              padTo(clip(verdict ? presentedName + '  ' + verdict : presentedName, nameW - 1), nameW) + C.reset
          );
        }
        if (s.deep.items.length > shown.length) {
          out.push(C.gray + '  \u2026 ' + t('tui.earlier', { n: s.deep.items.length - shown.length }) + C.reset);
        }
        return out;
      }

      // Russian column titles are wider than the data, so the widths are measured from the
      // rendered labels rather than hard-coded. The name columns then take whatever is left
      // with a floor, and the row is clipped rather than allowed to wrap.
      const certW = Math.max(width(t('tui.certificate')), width(t('tui.invalid'))) + 1;
      const fwdW = Math.max(width(t('tui.forward')), width(t('forward.comparable'))) + 1;
      const scoreW = width(t('tui.score')) + 1;
      const msW = width(t('tui.ms')) + 1;
      // 'candidate' and 'presented as' split the remainder evenly. They are distinct things:
      // on a catch-all host the second differs from the first on every row.
      const name = Math.max(14, Math.max(width(t('tui.candidate')), width(t('tui.presentedAs'))) + 1);
      const presented = Math.max(14, w - 4 - 2 - name - certW - fwdW - scoreW - msW);
      out.push(
        C.gray + '  ' +
          padTo(t('tui.candidate'), name) +
          padTo(t('tui.presentedAs'), presented) +
          padTo(t('tui.certificate'), certW) +
          padTo(t('tui.forward'), fwdW) +
          padToL(t('tui.score'), scoreW) +
          padToL(t('tui.ms'), msW) +
          C.reset
      );
      const shown = s.deep.items.slice(-rows);
      for (const c of shown) {
        const leaf = c.leaf;
        const presentedName = leaf && leaf.cn ? leaf.cn : '\u2014';
        const same = String(presentedName).toLowerCase() === String(c.name).toLowerCase();
        const certTxt = certLabel(c, t);
        const fwd = forwardLabel(c, t);
        const fwdColour =
          fwd === t('forward.identical') ? C.green
          : fwd === t('forward.comparable') ? C.cyan
          : fwd === t('forward.failed') || fwd === t('forward.differs') ? C.red
          : C.gray;
        out.push(
          '  ' +
            C.bold + padTo(clip(c.name, name - 1), name) + C.reset +
            (same ? C.gray : C.magenta) + padTo(clip(presentedName, presented - 1), presented) + C.reset +
            certColor(c) + padTo(certTxt, certW) + C.reset +
            fwdColour + padTo(fwd, fwdW) + C.reset +
            padToL(c.score == null ? '' : String(c.score), scoreW) +
            padToL(c.stability && c.stability.latencyMs ? String(round(c.stability.latencyMs.median, 0)) : '', msW)
        );
      }
      if (s.deep.items.length > shown.length) {
        out.push(C.gray + '  \u2026 ' + t('tui.earlier', { n: s.deep.items.length - shown.length }) + C.reset);
      }
    } else if (s.discovery.recent.length) {
      out.push(C.gray + t('tui.recent') + C.reset);
      const shown = s.discovery.recent.slice(-rowBudget(reserved + 1, s.discovery.recent.length));
      const markCol = 4;
      const verdict = Math.max(width(t('identity.accepted')), width(t('identity.rejected')));
      const nameW = Math.max(14, Math.floor((w - 4 - markCol - verdict) / 2));
      for (const r of shown) {
        const mark = r.accepted ? C.green + '\u2713' + C.reset : C.gray + '\u00b7' + C.reset;
        out.push(
          '  ' + mark + ' ' + padTo(clip(r.name, nameW - 1), nameW) +
            (r.accepted ? C.green + t('identity.accepted') + C.reset : C.gray + t('identity.rejected') + C.reset)
        );
      }
    } else if (!s.finished) {
      // Only while a scan is running: once it is over, "waiting for the first results" is a
      // contradiction, and an empty table says the same thing without the confusion.
      out.push(C.gray + t('tui.waiting') + C.reset);
    }
    return out;
  }

  /** Break plain text on spaces so a long line wraps instead of being cut mid-word. */
  function wrap(text, n) {
    const words = String(text).split(' ');
    const lines = [];
    let line = '';
    for (const word of words) {
      if (!line) line = word;
      else if (line.length + 1 + word.length <= n) line += ' ' + word;
      else {
        lines.push(line);
        line = word;
      }
    }
    if (line) lines.push(line);
    return lines.length ? lines : [''];
  }

  function footerLines(w) {
    const s = state;
    const body = [];
    const out = [];
    if (s.finished && s.result) {
      const r = s.result;
      const notes = []
        .concat((r.summary && r.summary.notes) || [])
        .concat(s.notes)
        .slice(0, 2);
      for (const note of notes) {
        body.push(field('tui.note', C.gray + clip(renderMsg(t, note), Math.max(10, w - 4 - LABEL)) + C.reset));
      }

      if (r.masking) {
        const m = r.masking;
        const tag = m.masking
          ? C.red + C.bold + '[!] ' + t('masking.detected') + C.reset
          : m.verdict === 'genuine-front'
          ? C.green + C.bold + '[ok] ' + t('masking.notDetected') + C.reset
          : C.yellow + C.bold + '[?] ' + t('masking.inconclusive') + C.reset;
        body.push(tag + C.gray + '  ' + t('method.' + m.method) + ' \u00b7 ' +
          t('masking.confidence') + ' ' + t('confidence.' + m.confidence) + C.reset);
      }

      if (r.best) {
        body.push(
          C.gray + t('tui.recommended') + C.reset + '  ' + C.bold + C.green + r.best.name + C.reset +
            C.gray + '   ' + r.best.score + '/100 \u00b7 ' + gradeText(t, r.best.grade) + C.reset
        );
        // The config is the one line people copy, so it is wrapped, never clipped.
        const config = '"serverNames": ["' + r.best.name + '"], "dest": "' + r.best.dest + '"';
        for (const part of wrap(config, Math.max(20, w - 4 - LABEL))) {
          body.push(C.gray + pad('', LABEL) + part + C.reset);
        }
      } else {
        body.push(C.yellow + t('tui.noName') + C.reset);
      }
    }
    // One separator, and only when there is something above it to separate from. The hint
    // line is always last so the frame height can be computed before the table is built.
    for (const l of body) out.push(l);
    if (body.length) out.push('');
    out.push(C.gray + (s.finished ? t('tui.quit') : t('tui.detachHint')) + C.reset);
    return out;
  }

  function frame() {
    if (stopped || state.detached) return;
    const w = columns();
    const hdr = headerLines(w);
    const progress = progressLines(w);
    const footer = footerLines(w);

    // The table gets whatever vertical space is left. Everything above and below it is
    // fixed-height, so the frame can be sized before the table is built and the newest
    // candidates are never the ones that get cut.
    // Every line that is not a candidate row: the two borders plus the header rows, the
    // progress block with its blank separators, the blank above the table, the blank below
    // it, and the footer. Counting this before the table is built is what keeps the newest
    // candidates — and the footer — on screen in a short terminal.
    const fixed = 2 + hdr.length + (progress.length ? progress.length + 2 : 1) + 1 + footer.length;
    const table = tableLines(w, fixed);

    const lines = boxLines(titleLine(w), hdr, w);
    if (progress.length) {
      lines.push('');
      for (const l of progress) lines.push(' ' + l);
    }
    if (table.length) {
      lines.push('');
      for (const l of table) lines.push(' ' + l);
    }
    lines.push('');
    for (const l of footer) lines.push(' ' + l);

    let out = HOME;
    const total = (process.stdout.rows || 40);
    const shown = lines.slice(0, total - 1);
    out += shown.map(function (l) { return frameCell(l, w) + '\n'; }).join('');
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

  function setTarget(target, index) {
    state.target = target;
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
    if (keyHandler) {
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
    // Wired up only for a real terminal. emitKeypressEvents puts stdin into flowing mode,
    // which keeps the process alive after the scan ends — so a caller that drives the TUI
    // without a terminal (tests) would hang on exit.
    if (process.stdin.isTTY) {
      readline.emitKeypressEvents(process.stdin);
      try {
        process.stdin.setRawMode(true);
      } catch (e) { /* ignore */ }
      process.stdin.resume();
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
    }
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
