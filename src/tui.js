// Terminal user interface.
//
// A dependency-free, in-place redrawing console UI: one frame per progress event,
// written with a cursor-home escape so the terminal never scrolls. Keys are read in raw
// mode. When stdout is not a TTY (piped, redirected, CI) the TUI degrades to plain
// line-by-line progress on stderr, and the report still goes to stdout untouched.
//
// Two things about this file are load-bearing and easy to get wrong:
//
//   * the local binding \`t\` is the TRANSLATOR for the whole factory. A local variable
//     named \`t\` anywhere in a draw function shadows it and throws "t is not a function"
//     on the very first frame. Target objects are called \`target\` here, never \`t\`.
//   * every measurement is in terminal CELLS (see cellWidth in util.js), never in
//     String#length. Cyrillic is one cell per character, but a full-width glyph — or a
//     colour escape counted as visible — shifts every column after it and the frame
//     shears, which is worse than a cosmetic flaw because the cursor arithmetic is
//     then wrong for every remaining row.
import readline from 'node:readline';
import {
  clip,
  clipCell,
  padCell,
  padCellL,
  cellWidth,
  stripAnsi,
  wrapCell,
  round
} from './util.js';
import { localizer, DEFAULT_LOCALE, LOCALE_NAMES, LOCALES } from './i18n/index.js';
import { renderMsg } from './messages.js';
import { FRAME_MIN } from './report.js';

const ESC = String.fromCharCode(27);
const CSI = ESC + '[';
const HIDE_CURSOR = CSI + '?25l';
const SHOW_CURSOR = CSI + '?25h';
const HOME = CSI + 'H';
const CLEAR_DOWN = CSI + 'J';

// Colour palette, chosen for contrast rather than for hue.
//
// The 16-colour ANSI table puts normal red at 2.71:1 and the 90m "bright black" that was
// used for secondary text at 2.82:1 against a black terminal — both below the 4.5:1 that
// WCAG 2.2 AA requires of body text. Terminals vary, but those two are the common case, so
// secondary text and failures use the bright variants, which clear the threshold on black
// and stay legible on the usual dark themes.
const PALETTE = {
  reset: CSI + '0m',
  bold: CSI + '1m',
  dim: CSI + '2m',
  red: CSI + '91m',
  green: CSI + '92m',
  yellow: CSI + '93m',
  blue: CSI + '94m',
  magenta: CSI + '95m',
  cyan: CSI + '96m',
  gray: CSI + '37m',
  inv: CSI + '7m'
};

// The live palette the draw functions read. Switched rather than blanked in place: writing
// empty strings into a shared object leaves every later instance in the process colourless.
const C = {};
function setColour(on) {
  for (const k of Object.keys(PALETTE)) C[k] = on ? PALETTE[k] : '';
}
setColour(true);

/** Visible width in cells, ignoring colour escapes. */
function width(s) {
  return cellWidth(s);
}

/** Pad or truncate to exactly n cells, keeping the colour escapes intact when it fits. */
function frameCell(s, n) {
  const str = String(s === undefined || s === null ? '' : s);
  if (width(str) <= n) return str + ' '.repeat(n - width(str)) + C.reset;
  // clipCell works on the plain text; colour is dropped rather than left unclosed, since
  // the frame is written as one buffer and an unterminated colour bleeds into every row.
  return clipCell(str, n) + C.reset;
}

function bar(fraction, cells, color) {
  const f = Math.max(0, Math.min(1, fraction || 0));
  const filled = Math.round(f * cells);
  const on = '\u2588'.repeat(filled);
  const off = '\u2591'.repeat(Math.max(0, cells - filled));
  return (color || C.cyan) + on + C.gray + off + C.reset;
}

function fmtDuration(ms) {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m < 60) return m + ':' + String(s).padStart(2, '0');
  return Math.floor(m / 60) + ':' + String(m % 60).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}

/**
 * Shape as well as colour for the score class.
 *
 * Colour alone is not a channel: it disappears under NO_COLOR, in a pipe, and for a reader
 * who cannot separate the hues. The cert and forward columns already pair colour with a
 * word; the score column now pairs it with a glyph.
 */
function gradeMark(grade) {
  if (grade === 'excellent' || grade === 'good') return '\u25cf';
  if (grade === 'fair') return '\u25cb';
  return '!';
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
  const ver = c && c.verified;
  if (!ver) return C.gray;
  if (ver.ok) return C.green;
  if (!ver.anchored) return C.red;
  return C.yellow;
}

function certLabel(c, t) {
  const ver = c && c.verified;
  if (!ver) return t('tui.pending');
  if (ver.ok) return t('tui.genuine');
  if (!ver.anchored) return t('tui.lookalike');
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
    // Navigation over the candidate table.
    selected: 0,
    scroll: 0,
    visibleRows: 0,
    // Follow the tail while a scan is running, so new results arrive in view. Any manual
    // navigation turns it off; returning to the last row turns it back on. Without this
    // the viewport would either fight the user or hide the newest candidates.
    follow: true,
    help: false,
    prompt: null,
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
  // Mutable on purpose: the language prompt can change it after the UI is already on
  // screen, and every draw function reads this binding.
  let t = typeof opts.t === 'function' ? opts.t : localizer(opts.locale || DEFAULT_LOCALE);
  const tty = opts.tty === undefined ? !!process.stdout.isTTY : !!opts.tty;
  const state = createState(opts.targets);
  let stopped = false;
  let keyHandler = null;
  let resizeHandler = null;
  let promptResolve = null;

  setColour(colour);

  // Below FRAME_MIN the frame cannot hold its own table, and the report renderer gives up
  // and wraps at the same point, so both sides agree on one floor instead of two.
  function columns() {
    return Math.max(FRAME_MIN, Math.min((process.stdout.columns || 100) - 1, 120));
  }

  function termRows() {
    return Math.max(12, process.stdout.rows || 30);
  }

  // One column for every field label, so the values line up instead of drifting with the
  // word length of whatever language is active. The width comes from the longest label in
  // the active locale — a fixed 10 clipped Russian "примечание" into "примечани…" — and is
  // capped so a wordy translation cannot push the value column off a narrow terminal.
  const LABEL_MAX = 22;

  function labelWidth(w) {
    let m = 0;
    for (const key of ['tui.target', 'tui.operator', 'tui.phase', 'tui.note']) m = Math.max(m, width(t(key)));
    const cap = w ? Math.max(8, Math.min(LABEL_MAX, w - 26)) : LABEL_MAX;
    return Math.min(m, cap) + 2;
  }

  /** Box-drawing frame: top border bearing the title, content rows, bottom border. */
  function boxLines(title, rows, w) {
    const inner = w - 2;
    const room = inner - 2;
    const head = ' ' + clipCell(title, Math.max(4, room - 1)) + ' ';
    const fill = '\u2500'.repeat(Math.max(0, inner - width(head) - 1));
    const out = [C.gray + '\u250c' + C.reset + head + C.gray + fill + '\u2510' + C.reset];
    for (const row of rows) {
      out.push(C.gray + '\u2502' + C.reset + ' ' + frameCell(row, room) + ' ' + C.gray + '\u2502' + C.reset);
    }
    out.push(C.gray + '\u2514' + '\u2500'.repeat(inner) + '\u2518' + C.reset);
    return out;
  }

  function brandTitle() {
    return C.bold + C.cyan + 'sni-recon' + C.reset + C.gray + ' \u00b7 ' + t('tui.title') + C.reset;
  }

  function field(label, value, pad) {
    return C.gray + padCell(clip(t(label), pad - 1), pad) + C.reset + value;
  }

  function rightAlign(left, right, inner) {
    return left + ' '.repeat(Math.max(1, inner - width(left) - width(right))) + right;
  }

  /** Header rows. The elapsed clock rides the target row so the title row stays clean. */
  function headerBox(w) {
    const s = state;
    const pad = labelWidth(w);
    const inner = w - 4;
    const rows = [];
    const target = s.target || {};
    const elapsed = C.gray + fmtDuration(Date.now() - s.started) + C.reset;

    let targetLine = C.bold + (target.address || '?') + C.reset + ':' + (target.port || 443);
    if (s.targets.length > 1) {
      targetLine += C.gray + ' [' + (s.targetIndex + 1) + '/' + s.targets.length + ']' + C.reset;
    }
    rows.push(rightAlign(field('tui.target', targetLine, pad), elapsed, inner));

    if (s.hoster && s.hoster.ok) {
      const bits = [s.hoster.asn, s.hoster.asName || s.hoster.org].filter(Boolean).join(' ');
      const place = s.hoster.city ? s.hoster.city + ', ' + (s.hoster.countryCode || '') : s.hoster.country || '';
      let line = C.magenta + clipCell(bits, 46) + C.reset;
      if (place) line += C.gray + ' \u00b7 ' + clipCell(place, 22) + C.reset;
      line += s.hoster.hosting
        ? C.yellow + '  [' + t('tui.datacenter') + ']' + C.reset
        : C.green + '  [' + t('tui.notDatacenter') + ']' + C.reset;
      rows.push(field('tui.operator', line, pad));
    }

    rows.push(field('tui.phase', C.bold + renderMsg(t, s.phaseMessage) + C.reset, pad));
    return boxLines(brandTitle(), rows, w);
  }

  const BAR_MAX = 40;

  function barCells(w, tail) {
    return Math.max(6, Math.min(BAR_MAX, w - 4 - labelWidth(w) - 2 - tail));
  }

  function progressLines(w) {
    const s = state;
    const pad = labelWidth(w);
    const out = [];
    if (s.phase === 'discovery' || s.phase === 'controls' || s.phase === 'init') {
      const d = s.discovery;
      const frac = d.total ? d.done / d.total : 0;
      const counts = d.done + '/' + d.total + ' ' + t('tui.probed') + ', ' +
        C.green + d.accepted + C.reset + ' ' + t('tui.accepted');
      out.push(field('tui.whitelist', bar(frac, barCells(w, width(counts)), C.cyan) + '  ' + counts, pad));
    }
    if (s.phase === 'deep') {
      const d = s.deep;
      const frac = d.total ? d.done / d.total : 0;
      const current = d.current ? C.gray + '  ' + clipCell(d.current, 28) + C.reset : '';
      const counts = d.done + '/' + d.total + current;
      out.push(field('tui.deep', bar(frac, barCells(w, width(counts)), C.cyan) + '  ' + counts, pad));
    }
    return out;
  }

  const TABLE_ROWS_MAX = 14;

  /** Column geometry for the candidate table, measured from the active locale's labels. */
  function tableColumns(w) {
    const pad = labelWidth(w);
    const certW = Math.max(width(t('tui.certificate')), width(t('tui.invalid'))) + 1;
    const fwdW = Math.max(width(t('tui.forward')), width(t('forward.comparable'))) + 1;
    // Scores reach -100 and a median latency is four digits under load, so the columns are
    // measured from the data: "62" and "138" must never touch.
    const scoreW = Math.max(width(t('tui.score')), width('-100')) + 2;
    const msW = Math.max(width(t('tui.ms')), width('9999')) + 2;
    const rankW = 3;
    const name = Math.max(16, Math.max(width(t('tui.candidate')), width(t('tui.presentedAs'))) + 1);
    const presented = Math.max(0, w - 2 - pad - rankW - name - certW - fwdW - scoreW - msW);
    return { pad: pad, rankW: rankW, name: name, presented: presented, certW: certW, fwdW: fwdW, scoreW: scoreW, msW: msW };
  }

  function tableBlock(w, budget) {
    const s = state;
    const out = [];
    const rows = s.deep.items;
    if (!rows.length) {
      if (s.discovery.recent.length) {
        out.push(C.gray + t('tui.recent') + C.reset);
        const shown = s.discovery.recent.slice(-Math.max(1, budget - 1));
        const verdictW = Math.max(width(t('identity.accepted')), width(t('identity.rejected')));
        const nameW = Math.max(14, Math.floor((w - 6 - verdictW) / 2));
        for (const r of shown) {
          const mark = r.accepted ? C.green + '\u2713' + C.reset : C.gray + '\u00b7' + C.reset;
          out.push('  ' + mark + ' ' + padCell(clipCell(r.name, nameW - 1), nameW) +
            (r.accepted ? C.green + t('identity.accepted') + C.reset : C.gray + t('identity.rejected') + C.reset));
        }
      } else if (!s.finished) {
        // Only while a scan is running: once it is over, "waiting for the first results"
        // is a contradiction, and an empty table says the same thing without the confusion.
        out.push(C.gray + t('tui.waiting') + C.reset);
      }
      return out;
    }

    const g = tableColumns(w);
    // The header is built from the same geometry the rows use. It previously indented by
    // pad + rankW and then left the rank column empty, so every heading sat four cells to
    // the right of the column it labelled.
    const head = '  ' + ' '.repeat(g.rankW + 1) +
      padCell(C.gray + t('tui.candidate') + C.reset, g.name) +
      padCell(C.gray + t('tui.presentedAs') + C.reset, g.presented) +
      padCell(C.gray + t('tui.certificate') + C.reset, g.certW) +
      padCell(C.gray + t('tui.forward') + C.reset, g.fwdW) +
      padCellL(C.gray + t('tui.score') + C.reset, g.scoreW) +
      padCellL(C.gray + t('tui.ms') + C.reset, g.msW);
    out.push(head);

    // Selection drives the viewport: the highlighted row is always on screen, and the
    // window slides only when the cursor would leave it.
    const visible = Math.max(1, Math.min(TABLE_ROWS_MAX, budget - out.length));
    s.visibleRows = visible;
    const maxFirst = Math.max(0, rows.length - visible);
    if (s.selected < s.scroll) s.scroll = s.selected;
    if (s.selected >= s.scroll + visible) s.scroll = s.selected - visible + 1;
    s.scroll = Math.max(0, Math.min(s.scroll, maxFirst));
    const shown = rows.slice(s.scroll, s.scroll + visible);

    for (let i = 0; i < shown.length; i++) {
      const c = shown[i];
      const idx = s.scroll + i;
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
      const cursor = idx === s.selected ? C.cyan + C.bold + '\u25b8 ' + C.reset : '  ';
      const line = cursor +
        (idx === s.selected ? C.cyan : C.gray) + padCellL(String(idx + 1), g.rankW) + C.reset + ' ' +
        (idx === s.selected ? C.bold : '') + padCell(clipCell(c.name, g.name - 1), g.name) + C.reset +
        (same ? C.gray : C.magenta) + padCell(clipCell(presentedName, Math.max(0, g.presented - 1)), g.presented) + C.reset +
        certColor(c) + padCell(certTxt, g.certW) + C.reset +
        fwdColour + padCell(fwd, g.fwdW) + C.reset +
        (c.score == null ? padCellL('', g.scoreW) : gradeColor(c.grade) + padCellL(gradeMark(c.grade) + ' ' + c.score, g.scoreW) + C.reset) +
        padCellL(c.stability && c.stability.latencyMs ? String(round(c.stability.latencyMs.median, 0)) : '', g.msW);
      out.push(line);
    }
    if (rows.length > shown.length) {
      const above = s.scroll;
      const below = rows.length - s.scroll - shown.length;
      const parts = [];
      if (above) parts.push('\u2191 ' + above);
      if (below) parts.push('\u2193 ' + below);
      // How much is out of view is stated rather than left to be inferred from a
      // silently truncated list.
      out.push(C.gray + '  ' + t('tui.more', { above: above, below: below }) + C.reset);
    }
    return out;
  }

  /** Word-wrap that never exceeds the frame. */
  function wrap(text, n) {
    return wrapCell(text, Math.max(12, n));
  }

  function footerBlock(w, budget) {
    const s = state;
    const pad = labelWidth(w);
    const out = [];
    if (s.help) {
      for (const line of helpRows(w)) out.push(line);
      if (budget !== undefined && out.length > budget) return out.slice(0, budget);
      return out;
    }
    if (s.finished && s.result) {
      const r = s.result;
      const notes = []
        .concat((r.summary && r.summary.notes) || [])
        .concat(s.notes)
        .slice(0, 2);
      for (const note of notes) {
        out.push(field('tui.note', C.gray + clipCell(renderMsg(t, note), Math.max(10, w - 4 - pad)) + C.reset, pad));
      }
      if (r.masking) {
        const m = r.masking;
        const tag = m.masking
          ? C.red + C.bold + '[!] ' + t('masking.detected') + C.reset
          : m.verdict === 'genuine-front'
          ? C.green + C.bold + '[ok] ' + t('masking.notDetected') + C.reset
          : C.yellow + C.bold + '[?] ' + t('masking.inconclusive') + C.reset;
        out.push(tag + C.gray + '  ' + t('method.' + m.method) + ' \u00b7 ' +
          t('masking.confidence') + ' ' + t('confidence.' + m.confidence) + C.reset);
      }
      if (r.best) {
        out.push(
          C.gray + t('tui.recommended') + C.reset + '  ' + C.bold + C.green + r.best.name + C.reset +
            C.gray + '   ' + r.best.score + '/100 \u00b7 ' + gradeText(t, r.best.grade) + C.reset
        );
        // The config is the one line people copy, so it is wrapped, never clipped.
        const config = '"serverNames": ["' + r.best.name + '"], "dest": "' + r.best.dest + '"';
        for (const part of wrap(config, w - 4 - pad)) {
          out.push(C.gray + ' '.repeat(pad) + part + C.reset);
        }
      } else {
        out.push(C.yellow + t('tui.noName') + C.reset);
      }
    }
    return out;
  }

  function helpRows(w) {
    const out = [C.bold + C.cyan + t('tui.help.title') + C.reset];
    for (const line of wrap(t('tui.help.body'), w - 2)) out.push(C.gray + line + C.reset);
    return out;
  }

  function hintLine() {
    const s = state;
    if (s.help) return t('tui.help.close');
    if (s.finished) return t('tui.quit');
    return t('tui.detachHint');
  }

  /** Height of the hint once it has wrapped to the frame width. */
  function hintHeight(w) {
    return Math.max(1, width(stripAnsi(hintLine())) > w - 2 ? 2 : 1);
  }

  function frame() {
    if (stopped || state.detached) return;
    const w = columns();
    const rows = termRows();
    let lines;
    if (state.prompt) {
      lines = promptFrame(w);
    } else {
      const header = headerBox(w);
      const progress = progressLines(w);
      const footer = footerBlock(w);
      // The table gets whatever vertical space is left. Everything above and below it is
      // fixed-height, so the frame can be sized before the table is built and the newest
      // candidates are never the ones that get cut.
      const fixed = header.length + 1 + (progress.length ? progress.length + 1 : 0) + 2 + hintHeight(w) + footer.length;
      const tableBudget = Math.max(2, rows - 1 - fixed);
      const table = tableBlock(w, tableBudget);
      lines = header.slice();
      if (progress.length) {
        lines.push('');
        for (const l of progress) lines.push(' ' + l);
      }
      lines.push('');
      for (const l of table) lines.push(' ' + l);
      lines.push('');
      for (const l of footer) lines.push(l);
    }
    for (const part of wrap(hintLine(), w - 2)) lines.push(' ' + C.gray + part + C.reset);

    let out = HOME;
    const shown = lines.slice(0, rows - 1);
    out += shown.map(function (l) { return frameCell(l, w) + '\n'; }).join('');
    out += CLEAR_DOWN;
    process.stdout.write(out);
    state.frames++;
  }

  function promptFrame(w) {
    const p = state.prompt;
    const body = [];
    body.push(' ' + C.bold + t('lang.prompt') + C.reset);
    body.push('');
    for (let i = 0; i < LOCALES.length; i++) {
      const loc = LOCALES[i];
      const mark = loc === p.highlight ? C.cyan + C.bold + '\u25b8' + C.reset : ' ';
      const hint = loc === p.default ? C.gray + '   (' + t('lang.default') + ')' + C.reset : '';
      body.push(' ' + mark + ' ' + C.bold + String(i + 1) + C.reset + '  ' + padCell(LOCALE_NAMES[loc] || loc, 14) + hint);
    }
    body.push('');
    for (const line of wrap(t('lang.remember'), w - 4)) body.push(C.gray + ' ' + line + C.reset);
    return boxLines(brandTitle(), body, w);
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
    // Once a candidate arrives it is finished, whatever the event counters still say.
    // Without this the header read "0/10" while rows were already on screen.
    state.deep.items.push(c);
    state.deep.done = Math.max(state.deep.done, state.deep.items.length);
    if (state.deep.items.length === 1) state.selected = 0;
    if (state.follow) state.selected = state.deep.items.length - 1;
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
    state.selected = 0;
    state.scroll = 0;
    state.follow = true;
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

  function moveSelection(delta) {
    const n = state.deep.items.length;
    if (!n) return;
    state.selected = Math.max(0, Math.min(n - 1, state.selected + delta));
    state.follow = state.selected === n - 1;
    frame();
  }

  function onKey(str, key) {
    if (!key) return;
    if (state.prompt) {
      const base = String(str || '').toLowerCase();
      if (key.name === 'return' || key.name === 'enter') {
        resolvePrompt(state.prompt.default);
        return;
      }
      if (key.ctrl && key.name === 'c') {
        process.stdout.write('\n');
        process.exit(130);
        return;
      }
      // The digit selects the row it is printed against, and the letter is a mnemonic for
      // the language's own name — Cyrillic 'р'/'у' included, since the prompt is answered
      // on a Russian keyboard as often as on a Latin one.
      const byIndex = /^[1-9]$/.test(base) ? LOCALES[Number(base) - 1] : null;
      if (byIndex) {
        resolvePrompt(byIndex);
        return;
      }
      if (base === 'r' || base === '\u043a' || base === '\u0440') {
        resolvePrompt('ru');
        return;
      }
      if (base === 'e' || base === '\u0443') {
        resolvePrompt('en');
        return;
      }
      if (key.name === 'up' || key.name === 'down') {
        const idx = LOCALES.indexOf(state.prompt.highlight);
        const next = Math.max(0, Math.min(LOCALES.length - 1, (idx < 0 ? 0 : idx) + (key.name === 'up' ? -1 : 1)));
        state.prompt.highlight = LOCALES[next];
        frame();
        return;
      }
      return;
    }
    if (key.ctrl && key.name === 'c') {
      stop();
      process.stdout.write('\n');
      process.kill(process.pid, 'SIGINT');
      return;
    }
    if (key.name === 'q' || key.name === 'escape') {
      if (state.help) {
        state.help = false;
        frame();
        return;
      }
      state.detached = true;
      process.stdout.write(CLEAR_DOWN + SHOW_CURSOR);
      process.stderr.write('[sni-recon] ' + t('progress.detached') + '\n');
      stop();
      return;
    }
    if (String(str) === '?') {
      state.help = !state.help;
      frame();
      return;
    }
    if (key.name === 'up') moveSelection(-1);
    else if (key.name === 'down') moveSelection(1);
    else if (key.name === 'pageup') moveSelection(-(state.visibleRows || 5));
    else if (key.name === 'pagedown') moveSelection(state.visibleRows || 5);
    else if (key.name === 'home') {
      state.selected = 0;
      state.follow = false;
      frame();
    } else if (key.name === 'end') {
      state.selected = Math.max(0, state.deep.items.length - 1);
      state.follow = true;
      frame();
    } else if (String(str) === 'c') {
      // Copy the recommended configuration to the log, so a keyboard-only session can
      // still get it out of the terminal without scrolling for it.
      const r = state.result;
      if (r && r.best) {
        process.stderr.write('[sni-recon] "' + '"serverNames": ["' + r.best.name + '"], "dest": "' + r.best.dest + '""\n');
      }
    }
  }

  function resolvePrompt(locale) {
    const fn = promptResolve;
    promptResolve = null;
    state.prompt = null;
    if (fn) fn(locale);
    else frame();
  }

  /**
   * Ask which language to use, in the terminal.
   *
   * Only asked on a real TTY: on a pipe there is nobody to answer, and blocking a CI job
   * on a keystroke would be a hang, not a question. The answer is returned rather than
   * applied, because the caller owns the .env and the message catalogue.
   */
  function promptLocale(defaultLocale) {
    if (!tty || opts.askLocale === false) return Promise.resolve(defaultLocale || DEFAULT_LOCALE);
    state.prompt = { highlight: defaultLocale || DEFAULT_LOCALE, default: defaultLocale || DEFAULT_LOCALE };
    frame();
    return new Promise(function (resolve) {
      promptResolve = resolve;
    });
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
      keyHandler = onKey;
      process.stdin.on('keypress', keyHandler);
    }
    resizeHandler = function () {
      frame();
    };
    process.stdout.on('resize', resizeHandler);
    frame();
  }

  /** Swap the catalogue under a running UI; the next frame is drawn in the new language. */
  function setLocale(locale) {
    const next = localizer(locale || DEFAULT_LOCALE);
    t = next;
    if (tty && !stopped) frame();
  }

  return {
    tty: tty,
    get t() {
      return t;
    },
    setLocale: setLocale,
    // Exposed so an embedding caller (and the test suite) can drive the UI without a
    // real terminal: the internal handler is only wired to stdin when stdin is a TTY.
    handleKey: onKey,
    start: start,
    stop: stop,
    finish: finish,
    onEvent: onEvent,
    addCandidate: addCandidate,
    setHoster: setHoster,
    setTarget: setTarget,
    promptLocale: promptLocale,
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

