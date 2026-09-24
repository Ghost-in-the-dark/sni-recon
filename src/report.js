// Report renderers: plain text, Markdown and JSON.
//
// Pure functions over the analysis object and a translator, so output is reproducible and
// diffable, and the same scan can be re-rendered in another locale without re-running it.
//
// Layout principle: the reader is told the ANSWER first. A conclusion block with the
// recommended name and its configuration sits at the top; the evidence that supports it
// sits directly under the same heading; the methodology, caveats and per-name appendix
// are pushed to the end, because they are the same in every report and are read once.
//
// The text renderer is the primary reading surface. It is built out of framed boxes and
// tables measured in TERMINAL CELLS, never in String#length: the report is written in
// Russian as often as in English, and Cyrillic is one cell per character, but any
// full-width glyph or colour escape used to shear every column after it.
import { pad, padL, clip, clipCell, padCell, padCellL, cellWidth, wrapCell, shortFp, round } from './util.js';
import { localizer, DEFAULT_LOCALE } from './i18n/index.js';
import { renderMsg, renderList } from './messages.js';

export const VERSION = '1.3.0';

const FENCE = String.fromCharCode(96).repeat(3);
const TICK = String.fromCharCode(96);
const DOT = '\u00b7';
const DASH = '\u2014';

/** Resolve a translator argument, so every renderer works with or without one. */
function translator(t) {
  if (typeof t === 'function') return t;
  if (t && typeof t.locale === 'string') return t;
  return localizer(DEFAULT_LOCALE);
}

function v(x, fallback) {
  return x === null || x === undefined || x === '' ? (fallback === undefined ? 'n/a' : fallback) : x;
}

function code(s) {
  return TICK + s + TICK;
}

/** Strip Markdown emphasis for the plain-text renderer. */
function plain(s) {
  return String(s === undefined || s === null ? '' : s).replace(/\*\*/g, '');
}

/** Capitalise a translated label that stands alone in a table cell. */
function cap(s) {
  const str = String(s === undefined || s === null ? '' : s);
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : str;
}

function gradeWord(t, grade) {
  return grade ? t('grade.' + grade) : grade;
}

function certVerdict(c, t) {
  const ver = c && c.verified;
  if (!ver) return t('cert.notInspected');
  if (ver.ok) return t('cert.genuine');
  if (!ver.anchored) return t('cert.lookalike');
  return t('cert.invalid');
}

/**
 * Short verdicts for the ranking table.
 *
 * The full wording ("genuine (chain verified)") is 32 cells and turns an eight-column
 * table into a wall of clipping on a narrow terminal. The table is for scanning; the exact
 * wording appears a few lines above in the summary and again in the appendix.
 */
function certShort(c, t) {
  const ver = c && c.verified;
  if (!ver) return t('cert.short.none');
  if (ver.ok) return t('cert.short.genuine');
  if (!ver.anchored) return t('cert.short.lookalike');
  return t('cert.short.invalid');
}

function forwardShort(c, t) {
  const f = c && c.forward;
  if (!f || !f.attempted) return DASH;
  if (f.error) return t('forward.short.failed');
  if (f.identityMatch === true) return t('forward.short.identical');
  if (f.comparable) return t('forward.short.comparable');
  return t('forward.short.differs');
}

function forwardVerdict(c, t) {
  const f = c && c.forward;
  if (!f || !f.attempted) return DASH;
  if (f.error) return t('forward.failed');
  if (f.identityMatch === true) return t('forward.identical');
  if (f.comparable) return t('forward.comparable');
  return t('forward.differs');
}

/** Dependencies handed to message rendering: a translator plus hoster composition. */
function deps(t) {
  return { t: t };
}

/** Format an ISO timestamp in the locale's own convention, degrading to the raw value. */
function formatDate(iso, locale) {
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return v(iso);
  try {
    return new Intl.DateTimeFormat(locale === 'ru' ? 'ru-RU' : 'en-GB', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: 'UTC'
    }).format(d) + ' UTC';
  } catch (e) {
    return d.toISOString();
  }
}

// ---------------------------------------------------------------------------
// Shared layout primitives (cell-accurate)
// ---------------------------------------------------------------------------

// The narrowest frame that can still hold the report's own tables. Exported because the
// live TUI draws the same kind of frame and the two disagreed: the TUI floored its width
// at 56 and the report at 46, which is one layout rule with two answers.
export const FRAME_MIN = 46;
const WRAP_MIN = 34;

/** Box-drawing frame. Width is in cells; every row is padded to exactly the inner width. */
export function frame(label, rows, w) {
  const width = Math.max(FRAME_MIN, w);
  const inner = width - 2;
  const room = inner - 2;
  const head = ' ' + clipCell(label, Math.max(4, room - 1)) + ' ';
  const fill = '\u2500'.repeat(Math.max(0, inner - cellWidth(head) - 1));
  const out = ['\u250c' + head + fill + '\u2510'];
  // clipCell as the last line of defence: a caller that hands over an over-long row must
  // not be able to break the frame. Layout code is expected to fit its content already.
  for (const row of rows) out.push('\u2502 ' + padCell(clipCell(row, room), room) + ' \u2502');
  out.push('\u2514' + '\u2500'.repeat(inner) + '\u2518');
  return out;
}

/** A section title line: marker, uppercase label, then a rule that reaches the margin. */
export function titleLine(text, w) {
  const head = '\u25b8 ' + text + ' ';
  const rest = Math.max(0, w - cellWidth(head));
  return head + '\u2500'.repeat(rest);
}

/**
 * Width of a label column, measured from the labels of the active locale.
 *
 * Every field() below pads to this width, but a translation can still be longer than the
 * width it was measured against (the latency label in Russian is longer than any of the
 * four labels the summary was sized from). padCell does not truncate, so the value would
 * end up glued to its label — "Медианная задержка рукопожатия132.7 ms". field() therefore
 * clips the label as well, which keeps one space between label and value whatever happens.
 */
function labelColumn(t, keys) {
  let m = 0;
  for (const k of keys) m = Math.max(m, cellWidth(t(k)));
  return m + 2;
}

function fieldLine(label, value, w) {
  return padCell(clipCell(label, w - 1), w) + value;
}

/** Index-pad: '\u2588 1. name' so the rank column is visually scannable. */
function numbered(i, text) {
  return String(i) + '. ' + text;
}

/**
 * Lays out fixed-width columns, clipping every cell and never overflowing the width.
 *
 * Column widths are measured from the rendered headers and cells — a longer Russian label
 * widens its column instead of colliding with its neighbour — and then shrunk until the
 * row fits the available width. Measuring alone is not enough: on a narrow terminal the
 * natural width of eight columns is wider than the report, and a row that overflows the
 * frame does not merely look wrong, it shears the box drawing and every line below it.
 */
function table(columns, rows, w) {
  const out = [];
  const gap = 2;
  const widths = columns.map(function (c, idx) {
    let m = cellWidth(c.label);
    for (const r of rows) m = Math.max(m, cellWidth(r[idx] === undefined || r[idx] === null ? '' : r[idx]));
    return Math.min(m + (c.pad || 0), c.max === undefined ? 60 : c.max);
  });
  const floors = columns.map(function (c) {
    return Math.max(3, c.min === undefined ? 5 : c.min);
  });
  const available = Math.max(24, w);
  let total = widths.reduce(function (a, b) { return a + b; }, 0) + gap * Math.max(0, widths.length - 1);
  // Take a cell from the widest column that can still give one, so the loss is spread
  // instead of emptying a single column.
  while (total > available) {
    let idx = -1;
    for (let i = 0; i < widths.length; i++) {
      if (widths[i] > floors[i] && (idx < 0 || widths[i] > widths[idx])) idx = i;
    }
    if (idx < 0) break;
    widths[idx]--;
    total--;
  }
  function line(cells) {
    const parts = [];
    for (let i = 0; i < columns.length; i++) {
      const raw = String(cells[i] === undefined || cells[i] === null ? '' : cells[i]);
      const txt = clipCell(raw, widths[i]);
      parts.push(columns[i].right ? padCellL(txt, widths[i]) : padCell(txt, widths[i]));
    }
    return parts.join(' '.repeat(gap)).replace(/ +$/, '');
  }
  out.push(line(columns.map(function (c) {
    return c.label;
  })));
  out.push('\u2500'.repeat(Math.min(w, totalWidth(widths, gap))));
  for (const r of rows) out.push(line(r));
  return out;
}

function totalWidth(widths, gap) {
  let s = 0;
  for (const w of widths) s += w;
  return s + gap * Math.max(0, widths.length - 1);
}

/**
 * Fit the frame to the terminal.
 *
 * Wrapping is always preferable to cutting, so a frame narrower than WRAP_MIN is not
 * squeezed further: it is wrapped at WRAP_MIN instead and the terminal soft-wraps the
 * result. The alternative — emitting a line longer than the frame — shears the box
 * drawing, which is what the previous version did on wide reports.
 */
function wrapAll(lines, w) {
  if (w >= WRAP_MIN) return lines;
  const out = [];
  for (const l of lines) {
    for (const part of wrapCell(l, WRAP_MIN)) out.push(part);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Plain text
// ---------------------------------------------------------------------------

export function renderText(result, tIn, options) {
  const t = translator(tIn);
  if (result.nodes) {
    return result.nodes
      .map(function (r) {
        return renderText(r, t, options);
      })
      .join('\n');
  }
  const W = Math.max(FRAME_MIN, (options && options.width) || 100);
  const n = result.node;
  const out = [];
  out.push('');
  // Wrapped, not just emitted: at --width 60 the title line measured 65 cells, which is the
  // one line in the report that could still reach past its own frame.
  for (const part of wrapPortable('sni-recon ' + VERSION + '  ' + n.address + ':' + n.port + '  ' + DOT + '  ' +
    formatDate(v(result.finishedAt, result.startedAt), t.locale), W)) {
    out.push(part);
  }
  out.push('='.repeat(W));

  if (!result.reachable) {
    out.push('');
    out.push(...frame(t('result.heading'), wrapPortable(t('result.noHandshake') + ' ' + renderMsg(t, result.summary && result.summary.message, deps(t)), W - 6), W));
    out.push('');
    out.push(...methodSection(t, W));
    out.push(...caveatSection(t, W));
    return wrapAll(out, W).join('\n');
  }

  out.push('');
  out.push(...frame(t('text.summary'), summaryRows(result, t, W), W));

  // Weight = the signals that actually moved the verdict. Four signals reading +1/+2/+1
  // under a lone "total weight 4" invited the reader to add them up and find they do not
  // sum to it, because a catch-all certificate is deliberately recorded at weight zero.
  out.push('');
  out.push(titleLine(t('progressSection').toUpperCase(), W));
  for (const l of bestStability(result, t, W)) out.push('  ' + l);
  out.push('');
  out.push(titleLine(t('verdictSection').toUpperCase(), W));
  for (const l of verdictLines(result, t, W)) out.push('  ' + l);

  const m = result.masking;
  if (m) {
    out.push('');
    out.push(...maskingSection(m, t, W));
  }

  out.push('');
  out.push(...rankingSection(result, t, W));

  const notes = renderList(t, result.summary && result.summary.notes, deps(t));
  if (notes.length) {
    out.push('');
    // NOT spread: titleLine returns a string, and pushing a spread string emits one
    // character per line.
    out.push(titleLine(t('notes.heading').toUpperCase(), W));
    for (const note of notes) {
      const lines = wrapPortable(note, W - 4);
      out.push('  ' + DOT + ' ' + lines[0]);
      for (let k = 1; k < lines.length; k++) out.push('    ' + lines[k]);
    }
  }

  if (result.whitelist && result.whitelist.rejectedSample && result.whitelist.rejectedSample.length) {
    out.push('');
    out.push(titleLine(t('rejected.heading').toUpperCase(), W));
    out.push(...wrapPortable(result.whitelist.rejectedSample.map(function (r) { return r.name; }).join(', '), W - 2).map(function (l) { return '  ' + l; }));
  }

  out.push('');
  out.push(...identitySection(result, t, W));

  out.push('');
  out.push(...detailSection(result, t, W));

  out.push('');
  out.push(...methodSection(t, W));
  out.push(...caveatSection(t, W));
  return wrapAll(out, W).join('\n');
}

function wrapPortable(text, w) {
  return wrapCell(plain(text), Math.max(16, w));
}

/** The answer, and the two or three facts that justify it, under one frame. */
function summaryRows(result, t, W) {
  const rows = [];
  const best = result.best;
  const weak = best && best.grade === 'poor';
  const labelW = labelColumn(t, ['text.recommend', 'text.score', 'text.certificate', 'text.forward', 'verdict.medianLatency', 'verdict.validFor']);
  function field(label, value) {
    return fieldLine(label, value, labelW);
  }
  if (!best) {
    rows.push(...wrapPortable(t('conclusion.noName'), W - 6));
    rows.push('');
    rows.push(...wrapPortable(renderMsg(t, result.summary && result.summary.message, deps(t)), W - 6));
    return rows;
  }
  rows.push(field(t('text.recommend'), best.name));
  rows.push(field(t('text.score'), best.score + ' / 100   ' + gradeWord(t, best.grade)));
  const bc = (result.candidates || []).find(function (c) {
    return c.name === best.name;
  });
  // Certificate and forward verdicts, latency and validity now sit in their own sections
  // directly below; the conclusion frame states the answer and the one line worth copying.
  rows.push('');
  // The configuration is the one line people copy, so an unusable name must not get one.
  if (!weak) {
    for (const part of wrapCell(t('conclusion.config') + ': ' + '"serverNames": [' + JSON.stringify(best.name) + '], "dest": ' + JSON.stringify(best.dest), W - 6)) {
      rows.push(part);
    }
  } else {
    for (const part of wrapCell(t('conclusion.warning'), W - 6)) rows.push(part);
  }
  return rows;
}

function maskingSection(m, t, W) {
  const out = [];
  const rows = [];
  const tag = m.masking ? t('masking.detected') : m.verdict === 'genuine-front' ? t('masking.notDetected') : t('masking.inconclusive');
  const claim = m.reasoning ? renderMsg(t, m.reasoning, deps(t)) : plain(renderMsg(t, m.headline, deps(t)));
  rows.push(...wrapCell(tag + '. ' + cap(claim), W - 6));
  rows.push('');
  const labelW = labelColumn(t, ['masking.method', 'masking.confidence', 'masking.weight', 'masking.nodeOperator', 'masking.referenceOperator', 'masking.sameOperator']);
  function field(k, val) {
    return fieldLine(k, val, labelW);
  }
  rows.push(field(t('masking.verdictKind'), cap(t('verdict.' + m.verdict))));
  rows.push(field(t('masking.method'), cap(t('method.' + m.method))));
  rows.push(field(t('masking.confidence'), t('confidence.' + m.confidence)));
  rows.push(field(t('masking.weight'), String(m.weight) + '  ' + DOT + '  ' + m.positiveSignals + ' ' + t('masking.signalsPositive')));
  if (m.nodeHoster) rows.push(field(t('masking.nodeOperator'), v(m.nodeHoster.description)));
  if (m.referenceHoster) rows.push(field(t('masking.referenceOperator'), v(m.referenceHoster.description)));
  if (m.sameOperator !== null && m.sameOperator !== undefined) {
    rows.push(field(t('masking.sameOperator'), t(m.sameOperator ? 'misc.yes' : 'misc.no')));
  }
  if (m.evidence && m.evidence.length) {
    rows.push('');
    for (const e of m.evidence) {
      const detail = plain(renderMsg(t, e.detail, deps(t)));
      const head = (e.weight > 0 ? '+' : '') + e.weight + '  ';
      const lines = wrapCell(detail, W - 8 - cellWidth(head));
      rows.push(padCell(head, 5) + lines[0]);
      for (let i = 1; i < lines.length; i++) rows.push(' '.repeat(5) + lines[i]);
    }
  }
  out.push(...frame(t('masking.heading'), rows, W));
  return out;
}

/**
 * Handshake statistics for the recommended name, kept out of the conclusion frame.
 *
 * These are measurements, not conclusions. Left inside the verdict frame they spent five
 * rows on numbers that qualify the answer rather than state it, and pushed the answer past
 * the first screenful on a small terminal.
 */
function bestStability(result, t, W) {
  const best = result.best;
  if (!best) return wrapPortable(t('conclusion.noName'), W - 4);
  const bc = (result.candidates || []).find(function (c) {
    return c.name === best.name;
  });
  if (!bc) return wrapPortable(t('conclusion.noName'), W - 4);
  const rows = [];
  const labelW = sectionLabelWidth(t, W);
  function field(label, value) {
    return fieldLine(label, value, labelW);
  }
  const st = bc.stability;
  if (st && st.attempts > 0) {
    rows.push(field(t('verdict.handshakes'), st.ok + ' / ' + st.attempts));
    rows.push(field(t('stability.label'), t(st.deterministic ? 'stability.deterministic' : 'stability.varied')));
    if (st.latencyMs && st.latencyMs.median != null) {
      rows.push(field(t('verdict.medianLatency'), st.latencyMs.median + ' ' + t('unit.ms')));
      rows.push(field(t('stability.spread'), st.latencyMs.min + ' / ' + st.latencyMs.max + ' ' + t('unit.ms')));
    }
  }
  if (bc.validityDaysLeft != null) {
    rows.push(field(t('verdict.validFor'), bc.validityDaysLeft + ' ' + t('verdict.days')));
  }
  return rows.length ? rows : wrapPortable(t('appendix.noDeep', { code: code('--no-deep') }), W - 4);
}

/**
 * Label column for the sections below the conclusion.
 *
 * 24 cells clipped the longest Russian labels — "Сертификат действителен ещё" came out as
 * "Сертификат действителе…" — so the column is measured from the labels themselves, with a
 * ceiling so a wordy translation cannot push the values off a narrow frame.
 */
function sectionLabelWidth(t, W) {
  return Math.max(12, Math.min(34, Math.max(W - 34, labelColumn(t, [
    'verdict.handshakes',
    'stability.label',
    'verdict.medianLatency',
    'stability.spread',
    'verdict.validFor',
    'text.certificate',
    'text.forward'
  ]))));
}

/** The verdict words that stand on their own, in the order they are asked about. */
function verdictLines(result, t, W) {
  const best = result.best;
  if (!best) return [];
  const bc = (result.candidates || []).find(function (c) {
    return c.name === best.name;
  });
  const rows = [];
  const labelW = sectionLabelWidth(t, W);
  rows.push(fieldLine(t('text.certificate'), certVerdict(bc, t), labelW));
  rows.push(fieldLine(t('text.forward'), forwardVerdict(bc, t), labelW));
  return rows;
}

function rankingSection(result, t, W) {
  const out = [titleLine(t('ranking.heading').toUpperCase(), W)];
  const rows = result.candidates || [];
  if (!rows.length) {
    out.push(...wrapPortable(t('conclusion.noName'), W - 2).map(function (l) { return '  ' + l; }));
    return out;
  }
  const cert = rows.map(function (x) { return certShort(x, t); });
  const fwd = rows.map(function (x) { return forwardShort(x, t); });
  const columns = [
    { label: t('ranking.rank'), max: 4, right: true },
    { label: t('ranking.name'), max: 44, min: 14 },
    { label: t('ranking.group'), max: 16 },
    { label: t('ranking.score'), max: 6, right: true },
    { label: t('ranking.grade'), max: 12 },
    { label: t('ranking.certificate'), max: 20 },
    { label: t('ranking.forward'), max: 14 },
    { label: t('ranking.medianMs'), max: 12, right: true }
  ];
  // One decimal, always: a column that renders "127" beside "134.8" reads as two different
  // measurements rather than one rounded one.
  const ms = function (x) {
    const m = x.stability && x.stability.latencyMs ? x.stability.latencyMs.median : null;
    return m === null || m === undefined ? DASH : Number(m).toFixed(1);
  };
  // Progressive degradation as the terminal narrows. 'group' is the least informative
  // column, so it goes first; then the two verdict columns fold into one cell rather than
  // one of them being dropped, because "genuine but not forwarding" and "lookalike but
  // forwarding" are different answers and neither column alone distinguishes them.
  const variants = [
    {
      columns: [
        { label: t('ranking.rank'), max: 4, right: true },
        { label: t('ranking.name'), max: 44, min: 14 },
        { label: t('ranking.group'), max: 16 },
        { label: t('ranking.score'), max: 6, right: true },
        { label: t('ranking.grade'), max: 12 },
        { label: t('ranking.certificate'), max: 34 },
        { label: t('ranking.forward'), max: 16 },
        { label: t('ranking.medianMs'), max: 12, right: true }
      ],
      cells: function (x, i) {
        return [String(i + 1), x.name, v(x.group), v(x.score), gradeWord(t, x.grade), cert[i], fwd[i], ms(x)];
      }
    },
    {
      columns: [
        { label: t('ranking.rank'), max: 4, right: true },
        { label: t('ranking.name'), max: 44, min: 14 },
        { label: t('ranking.score'), max: 6, right: true },
        { label: t('ranking.grade'), max: 14 },
        { label: t('ranking.certificate'), max: 34 },
        { label: t('ranking.forward'), max: 16 },
        { label: t('ranking.medianMs'), max: 12, right: true }
      ],
      cells: function (x, i) {
        return [String(i + 1), x.name, v(x.score), gradeWord(t, x.grade), cert[i], fwd[i], ms(x)];
      }
    },
    {
      columns: [
        { label: t('ranking.rank'), max: 4, right: true },
        { label: t('ranking.name'), max: 44, min: 14 },
        { label: t('ranking.score'), max: 6, right: true },
        { label: t('ranking.grade'), max: 14 },
        { label: t('ranking.certificate'), max: 34 },
        { label: t('ranking.medianMs'), max: 12, right: true }
      ],
      cells: function (x, i) {
        return [String(i + 1), x.name, v(x.score), gradeWord(t, x.grade), cert[i] + ' / ' + fwd[i], ms(x)];
      }
    }
  ];
  let chosen = variants[variants.length - 1];
  for (const variant of variants) {
    if (estimatedWidth(variant.columns, rows, variant.cells) <= W - 2) {
      chosen = variant;
      break;
    }
  }
  const data = rows.map(chosen.cells);
  // A column that is empty in every row carries no information and only costs width. On a
  // single-target scan the group column is 'n/a' ten times over.
  const empty = chosen.columns.map(function (c, i) {
    return data.every(function (row) {
      const cell = row[i];
      return cell === undefined || cell === null || String(cell).trim() === '' || String(cell) === 'n/a';
    });
  });
  if (empty.some(Boolean)) {
    for (let i = chosen.columns.length - 1; i >= 0; i--) {
      if (!empty[i] || i === 0) continue;
      chosen.columns.splice(i, 1);
      for (const row of data) row.splice(i, 1);
    }
  }
  // A long run of identical scores is one finding, not ten rows of evidence.
  const collapsed = collapseTies(chosen.columns, data, t);
  const shown = collapsed ? collapsed.rows : data;
  // Two cells are spent on the indent, so the grid has to fit in W - 2.
  const grid = table(collapsed ? collapsed.columns : chosen.columns, shown, W - 2);
  for (const l of grid) out.push('  ' + l);
  if (collapsed && collapsed.tied) {
    out.push('  ' + t('ranking.sameRows', { n: collapsed.tied.n, score: collapsed.tied.score }));
  }
  return out;
}

/**
 * Collapse a run of identical trailing rows into one line.
 *
 * A scan that accepts many names but trusts none of them produces eight rows of "-38" whose
 * only shared meaning is "these were all rejected the same way". Printing all of them buries
 * the one row that differs.
 */
function collapseTies(columns, data, t) {
  if (data.length < 6) return null;
  const scoreIdx = columns.findIndex(function (c) { return c.label === t('ranking.score'); });
  const latIdx = columns.findIndex(function (c) { return c.label === t('ranking.medianMs'); });
  if (scoreIdx < 0) return null;
  // Rank (0), name (1) and latency differ for reasons that are not the score, so the run is
  // measured over the remaining verdict columns.
  const compare = [];
  for (let i = 2; i < columns.length; i++) if (i !== latIdx) compare.push(i);
  const key = function (row) {
    return compare.map(function (i) { return String(row[i]); }).join('\u0000');
  };
  // The longest run of consecutive identical rows anywhere in the table, not just at the
  // tail: the run of rejected names sits in the middle, above one that scored differently.
  let best = { first: 0, size: 0 };
  let i = 0;
  while (i < data.length) {
    let j = i + 1;
    while (j < data.length && key(data[j]) === key(data[i])) j++;
    if (j - i > best.size) best = { first: i, size: j - i };
    i = j;
  }
  if (best.size < 3) return null;
  // The collapsed run becomes one line *below* the grid rather than a row inside it: as a
  // row it is clipped to the name column, which is how "ещё 5 имён…" became "ещё 5 им…".
  const rows = data.slice(0, best.first).concat(data.slice(best.first + best.size));
  // Ranks are positions, so they are renumbered over what is actually shown; leaving the
  // original numbers would read as three missing rows.
  for (let k = 0; k < rows.length; k++) rows[k] = rows[k].slice(), rows[k][0] = String(k + 1);
  return {
    columns: columns,
    rows: rows,
    tied: { n: best.size, score: String(data[best.first][scoreIdx]) }
  };
}

function estimatedWidth(columns, rows, cellsFor) {
  let total = 0;
  for (let i = 0; i < columns.length; i++) {
    let m = cellWidth(columns[i].label);
    for (let r = 0; r < rows.length; r++) m = Math.max(m, cellWidth(cellsFor(rows[r], r)[i]));
    total += Math.min(m, columns[i].max === undefined ? 60 : columns[i].max);
  }
  return total + 2 * Math.max(0, columns.length - 1) + 2;
}

function identitySection(result, t, W) {
  const out = [];
  const rows = [];
  if (result.hoster && result.hoster.ok) {
    rows.push(...wrapCell(describeOperator(result.hoster, t), W - 6));
    rows.push('');
  }
  const c = result.controls || {};
  const grid = table(
    [
      { label: t('identity.probe'), max: 26 },
      { label: t('identity.handshake'), max: 12 },
      { label: t('identity.leafCn'), max: 30 },
      { label: t('identity.anchored'), max: 24 }
    ],
    [
      [
        t('identity.noSni'),
        t(c.noSni && c.noSni.ok ? 'identity.ok' : 'identity.failed'),
        v(c.noSni && c.noSni.leafCn, DASH),
        c.noSni ? t(c.noSni.anchored ? 'misc.yes' : 'misc.no') : DASH
      ],
      [
        v(c.strictName && c.strictName.name, 'invalid2.invalid'),
        t(c.strictName && c.strictName.ok ? 'identity.accepted' : 'identity.rejected'),
        v(c.strictName && c.strictName.leafCn, DASH),
        DASH
      ],
      [
        t('identity.randomName'),
        t(c.randomName && c.randomName.ok ? 'identity.accepted' : 'identity.rejected'),
        v(c.randomName && c.randomName.leafCn, DASH),
        DASH
      ]
    ],
    W - 4
  );
  for (const l of grid) rows.push(l);
  const wl = result.whitelist || {};
  rows.push('');
  for (const line of [
    t('identity.namesTested') + ': ' + wl.tested + '   ' + DOT + '   ' +
      t('identity.namesAccepted') + ': ' + wl.accepted + '   ' + DOT + '   ' +
      t('identity.distinctCerts') + ': ' + v(wl.distinctIdentities),
    t('identity.generic') + ': ' + t(wl.genericIdentity ? 'misc.yes' : 'misc.no') + '   ' + DOT + '   ' +
      t('identity.arbitrary') + ': ' + t(wl.randomNameAccepted ? 'misc.yes' : 'misc.no') + '   ' + DOT + '   ' +
      t('identity.strictCompatible') + ': ' + t(wl.realitlscannerCompatible ? 'misc.yes' : 'misc.no')
  ]) {
    for (const part of wrapCell(line, W - 8)) rows.push(part);
  }
  return [...out, ...frame(t('identity.heading'), rows, W)];
}

/** Operator description is composed here rather than baked into the analysis result. */
function describeOperator(h, t) {
  const bits = [];
  if (h.asn) bits.push(h.asn + (h.asName ? ' ' + h.asName : ''));
  else if (h.org) bits.push(h.org);
  else if (h.isp) bits.push(h.isp);
  const place = [h.city, h.countryCode].filter(Boolean).join(', ');
  if (place) bits.push(place);
  let line = bits.join(' ' + DOT + ' ') || t('misc.unknown');
  line += '  [' + t(h.hosting ? 'tui.datacenter' : 'tui.notDatacenter') + ']';
  return line;
}

function detailSection(result, t, W) {
  const out = [titleLine(t('appendix.detail').toUpperCase(), W)];
  const rows = (result.candidates || []).filter(function (x) {
    return x.stability;
  });
  if (!rows.length) {
    out.push(...wrapPortable(t('appendix.noDeep', { code: code('--no-deep') }), W - 2).map(function (l) { return '  ' + l; }));
    return out;
  }
  for (let i = 0; i < rows.length; i++) {
    const x = rows[i];
    out.push('');
    out.push('  ' + numbered(i + 1, x.name + '  ' + DASH + '  ' + x.score + '/100 (' + gradeWord(t, x.grade) + ')'));
    if (x.leaf) {
      const certRows = [];
      const certLabels = ['Subject CN', 'Issuer CN', 'Valid from', 'Valid to', 'SHA-256', t('compare.leaf')];
      let labelW = 0;
      for (const label of certLabels) labelW = Math.max(labelW, cellWidth(label) + 2);
      certRows.push(fieldLine('Subject CN', v(x.leaf.cn), labelW));
      certRows.push(fieldLine('Issuer CN', v(x.leaf.issuerCn), labelW));
      certRows.push(fieldLine('Valid from', v(x.leaf.validFrom), labelW));
      certRows.push(fieldLine('Valid to', v(x.leaf.validTo), labelW));
      certRows.push(fieldLine('SHA-256', v(shortFp(x.leaf.fingerprint256), '') + '…', labelW));
      if (x.reference && x.reference.leafFingerprint256) {
        const same = x.leaf.fingerprint256 === x.reference.leafFingerprint256;
        certRows.push(fieldLine(t('compare.leaf'), t(same ? 'compare.identical' : 'compare.differ'), labelW));
      }
      out.push(...indent(frame(t('text.certificate'), certRows, W - 4), 4));
    }
    if (x.scoreComponents && x.scoreComponents.length) {
      const scoreRows = [];
      let reasonW = 0;
      for (const comp of x.scoreComponents) reasonW = Math.max(reasonW, cellWidth(plain(renderMsg(t, comp.reason, deps(t)))));
      for (const comp of x.scoreComponents) {
        const pts = (comp.points > 0 ? '+' : '') + comp.points;
        const reason = plain(renderMsg(t, comp.reason, deps(t)));
        const lines = wrapCell(reason, Math.max(12, W - 12 - 5));
        scoreRows.push(padCellL(pts, 5) + '  ' + lines[0]);
        for (let k = 1; k < lines.length; k++) scoreRows.push(' '.repeat(7) + lines[k]);
      }
      out.push(...indent(frame(t('text.score'), scoreRows, W - 4), 4));
    }
    const cmp = comparisonFrame(x, t, W - 4);
    if (cmp) out.push(...indent(cmp, 4));
    if (x.forward && x.forward.assets && x.forward.assets.length) {
      const assetRows = x.forward.assets.map(function (a) {
        return a.path + '  ' + DOT + '  ' + t('compare.throughNode') + ': ' +
          (a.via.error ? a.via.error : a.via.bytes + ' B') + '  ' + DOT + '  ' +
          t('compare.realSite') + ': ' + (a.direct.error ? a.direct.error : a.direct.bytes + ' B') +
          '  ' + DOT + '  ' + t(a.identical ? 'compare.identical' : 'compare.differ');
      });
      out.push(...indent(frame(t('assets.heading'), assetRows, W - 4), 4));
    }
    if (x.stability) {
      const lines = wrapPortable(t('stability.line', {
        ok: x.stability.ok,
        attempts: x.stability.attempts,
        determinism: t(
          x.stability.attempts > 0
            ? x.stability.deterministic
              ? 'stability.deterministic'
              : 'stability.varied'
            : 'stability.unknown'
        ),
        min: v(x.stability.latencyMs.min),
        median: v(x.stability.latencyMs.median),
        max: v(x.stability.latencyMs.max)
      }), W - 8);
      out.push('    ' + lines[0]);
      for (let k = 1; k < lines.length; k++) out.push('      ' + lines[k]);
    }
    if (x.forward && x.forward.differences && x.forward.differences.length) {
      out.push('    ' + t('differences.heading') + ':');
      for (const d of renderList(t, x.forward.differences, deps(t))) {
        const lines = wrapPortable(d, W - 10);
        out.push('      ' + DOT + ' ' + lines[0]);
        for (let k = 1; k < lines.length; k++) out.push('        ' + lines[k]);
      }
    }
  }
  return out;
}

function comparisonFrame(x, t, w) {
  const f = x.forward;
  if (!f || !f.attempted) return null;
  // A frame that measured nothing is not a comparison. Rendering the grid with empty cells
  // and "not comparable" verdicts beside a line claiming the behaviour was identical is
  // worse than omitting it.
  if (!f.error && (!f.via || !f.direct)) return null;
  const label = t('compare.heading') + (x.reference && x.reference.address ? ' ' + DOT + ' ' + t('compare.referenceAddress') + ': ' + x.reference.address : '');
  const rows = [];
  if (f.error) {
    rows.push(...wrapCell(t('forward.failed') + ': ' + f.error, w - 6));
    return frame(label, rows, w);
  }
  const vd = f.verdicts || {};
  const word = function (k) {
    return t('compare.' + (k || 'differ'));
  };
  if (f.via && f.direct) {
    const grid = table(
      [
        { label: t('compare.check'), max: 22 },
        { label: t('compare.throughNode'), max: 24 },
        { label: t('compare.realSite'), max: 24 },
        { label: t('compare.result'), max: 16 }
      ],
      [
        [t('compare.status'), String(f.via.status), String(f.direct.status), word(vd.status)],
        [t('compare.bytes'), f.via.bytes + ' B', f.direct.bytes + ' B', word(vd.bytes)],
        [t('compare.bodyHash'), shortHash(f.via.bodyHash), shortHash(f.direct.bodyHash), word(vd.bodyHash)],
        [t('compare.timing'), v(f.via.ttfbMs) + ' ' + t('unit.ms'), v(f.direct.ttfbMs) + ' ' + t('unit.ms'), DASH],
        [t('compare.hopCount'), String(hopCount(f.via.hops)), String(hopCount(f.direct.hops)), DASH]
      ],
      w - 4
    );
    for (const l of grid) rows.push(l);
    if (f.leafFingerprint256 || (x.reference && x.reference.leafFingerprint256)) {
      rows.push(t('compare.leaf') + ': ' + shortHash(f.leafFingerprint256) + '  ' + DOT + '  ' +
        shortHash(x.reference && x.reference.leafFingerprint256) + '  ' + DOT + '  ' + word(vd.leafFingerprint));
    }
  }
  return frame(label, rows, w);
}

function indent(lines, n) {
  const pad = ' '.repeat(n);
  return lines.map(function (l) {
    return pad + l;
  });
}

function methodSection(t, W) {
  const out = ['', titleLine(plain(t('method.heading')).toUpperCase(), W)];
  const steps = [t('method.step1'), t('method.step2'), t('method.step3'), t('method.step4', { code: code('Host') })];
  for (let i = 0; i < steps.length; i++) {
    const lines = wrapPortable(steps[i], W - 6);
    out.push('  ' + labelIndex(i + 1) + lines[0]);
    for (let k = 1; k < lines.length; k++) out.push('     ' + lines[k]);
  }
  out.push('');
  out.push(...wrapPortable(t('method.controls', { code: code('invalid2.invalid') }), W - 2).map(function (l) { return '  ' + l; }));
  return out;
}

function caveatSection(t, W) {
  const out = ['', titleLine(plain(t('caveats.heading')).toUpperCase(), W)];
  for (const c of [t('caveat.chain'), t('caveat.sample'), t('caveat.personalised', { code: code('--assets') }), t('caveat.vantage')]) {
    const lines = wrapPortable(c, W - 4);
    out.push('  ' + DOT + ' ' + lines[0]);
    for (let k = 1; k < lines.length; k++) out.push('    ' + lines[k]);
  }
  return out;
}

function labelIndex(i) {
  return i + ') ';
}

/** Redirect count. `hops` is the list of hops, so its length is the number, not the list. */
function hopCount(hops) {
  return Array.isArray(hops) ? hops.length : 0;
}

function shortHash(h) {
  if (!h) return DASH;
  const compact = String(h).replace(/:/g, '');
  return compact.slice(0, 12).toUpperCase() + '\u2026';
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

export function renderMarkdown(result, tIn) {
  const t = translator(tIn);
  if (result.nodes) {
    return result.nodes
      .map(function (r) {
        return renderMarkdown(r, t);
      })
      .join('\n\n---\n\n');
  }
  const L = [];
  const n = result.node;
  L.push('# ' + t('doc.title', { address: n.address, port: n.port }));
  L.push('');
  L.push(t('doc.generated', { at: formatDate(v(result.finishedAt, result.startedAt), t.locale), version: VERSION }));
  L.push('');

  if (!result.reachable) {
    L.push('## ' + t('result.heading'));
    L.push('');
    L.push(t('result.noHandshake'));
    L.push('');
    L.push(renderMsg(t, result.summary && result.summary.message, deps(t)));
    L.push('');
    appendMethodAndCaveats(L, t);
    return L.join('\n');
  }

  // --- Conclusion: the answer, and the evidence for it, under one heading ----
  L.push('## ' + t('conclusion.heading'));
  L.push('');
  if (result.best) {
    const weak = result.best.grade === 'poor';
    // A name that scored poorly is not a recommendation. Handing the reader a
    // ready-to-paste configuration for it would be actively misleading, so the block is
    // replaced by an explicit statement that nothing here is usable.
    L.push(
      weak
        ? t('conclusion.bestWeak', { name: result.best.name, score: result.best.score, grade: gradeWord(t, result.best.grade) })
        : t('conclusion.best', { name: result.best.name, score: result.best.score, grade: gradeWord(t, result.best.grade) })
    );
    L.push('');
    for (const line of conclusionEvidence(result, t)) L.push('- ' + line);
    L.push('');
    if (weak) {
      L.push('> ' + t('conclusion.warning'));
      L.push('');
    }
    if (!weak) {
      L.push('### ' + t('conclusion.config'));
      L.push('');
      L.push(FENCE + 'json');
      L.push('"serverNames": [' + JSON.stringify(result.best.name) + '],');
      L.push('"dest": ' + JSON.stringify(result.best.dest));
      L.push(FENCE);
      L.push('');
      L.push(t('conclusion.configNote', { code: code('dest') }));
      L.push('');
    }
    L.push('| ' + t('table.field') + ' | ' + t('table.value') + ' |');
    L.push('| --- | --- |');
    const bc = (result.candidates || []).find(function (c) {
      return c.name === result.best.name;
    });
    L.push('| ' + t('verdict.score') + ' | ' + result.best.score + ' / 100 (' + gradeWord(t, result.best.grade) + ') |');
    if (bc && bc.stability) {
      L.push('| ' + t('verdict.handshakes') + ' | ' + bc.stability.ok + '/' + bc.stability.attempts + ' |');
    }
    if (bc && bc.stability && bc.stability.latencyMs.median != null) {
      L.push('| ' + t('verdict.medianLatency') + ' | ' + bc.stability.latencyMs.median + ' ' + t('unit.ms') + ' |');
    }
    if (bc && bc.validityDaysLeft != null) {
      L.push('| ' + t('verdict.validFor') + ' | ' + bc.validityDaysLeft + ' ' + t('verdict.days') + ' |');
    }
    L.push('| ' + t('verdict.certificate') + ' | ' + certVerdict(bc, t) + ' |');
    L.push('| ' + t('verdict.forwarding') + ' | ' + forwardVerdict(bc, t) + ' |');
    L.push('');
  } else {
    L.push(t('conclusion.noName'));
    L.push('');
    L.push(renderMsg(t, result.summary && result.summary.message, deps(t)));
    L.push('');
  }

  // Masking verdict belongs with the conclusion, not in an appendix: it is a finding.
  const m = result.masking;
  if (m) {
    L.push('### ' + t('masking.heading'));
    L.push('');
    const tag = m.masking ? t('masking.detected') : m.verdict === 'genuine-front' ? t('masking.notDetected') : t('masking.inconclusive');
    L.push('**' + tag + '** ' + DASH + ' ' + renderMsg(t, m.headline, deps(t)));
    L.push('');
    L.push('| ' + t('table.field') + ' | ' + t('table.value') + ' |');
    L.push('| --- | --- |');
    L.push('| ' + t('masking.verdictKind') + ' | ' + code(cap(t('verdict.' + m.verdict))) + ' |');
    L.push('| ' + t('masking.method') + ' | ' + code(cap(t('method.' + m.method))) + ' |');
    L.push('| ' + t('masking.confidence') + ' | ' + t('confidence.' + m.confidence) + ' |');
    L.push('| ' + t('masking.weight') + ' | ' + m.weight + ' (' + m.positiveSignals + ' ' + t('masking.signalsPositive') + ') |');
    if (m.nodeHoster) {
      L.push('| ' + t('masking.nodeOperator') + ' | ' + v(m.nodeHoster.description) + ' |');
      L.push('| ' + t('masking.datacenter') + ' | ' + t(m.nodeHoster.hosting ? 'misc.yes' : 'misc.no') + ' |');
    }
    if (m.referenceHoster) L.push('| ' + t('masking.referenceOperator') + ' | ' + v(m.referenceHoster.description) + ' |');
    if (m.sameOperator !== null && m.sameOperator !== undefined) {
      L.push('| ' + t('masking.sameOperator') + ' | ' + t(m.sameOperator ? 'misc.yes' : 'misc.no') + ' |');
    }
    L.push('');
    if (m.evidence && m.evidence.length) {
      L.push('| ' + t('masking.evidence') + ' | ' + t('masking.evidenceWeight') + ' | ' + t('masking.evidenceDetail') + ' |');
      L.push('| --- | --- | --- |');
      for (const e of m.evidence) {
        L.push('| ' + code(e.signal) + ' | ' + (e.weight > 0 ? '+' : '') + e.weight + ' | ' + renderMsg(t, e.detail, deps(t)) + ' |');
      }
      L.push('');
    }
  }

  // --- Ranking --------------------------------------------------------------
  L.push('## ' + t('ranking.heading'));
  L.push('');
  L.push('| ' + t('ranking.rank') + ' | ' + t('ranking.name') + ' | ' + t('ranking.group') + ' | ' + t('ranking.score') + ' | ' + t('ranking.grade') + ' | ' + t('ranking.certificate') + ' | ' + t('ranking.forward') + ' | ' + t('ranking.medianMs') + ' |');
  L.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
  const rows = result.candidates || [];
  for (let i = 0; i < rows.length; i++) {
    const x = rows[i];
    const ms = x.stability && x.stability.latencyMs ? x.stability.latencyMs.median : null;
    L.push(
      '| ' + (i + 1) +
      ' | ' + code(x.name) +
      ' | ' + v(x.group) +
      ' | ' + v(x.score) +
      ' | ' + v(gradeWord(t, x.grade)) +
      ' | ' + certVerdict(x, t) +
      ' | ' + forwardVerdict(x, t) +
      ' | ' + v(ms) + ' |'
    );
  }
  L.push('');

  if (result.summary && result.summary.notes && result.summary.notes.length) {
    L.push('## ' + t('notes.heading'));
    L.push('');
    for (const note of renderList(t, result.summary.notes, deps(t))) L.push('- ' + note);
    L.push('');
  }
  if (result.whitelist && result.whitelist.rejectedSample && result.whitelist.rejectedSample.length) {
    L.push('## ' + t('rejected.heading'));
    L.push('');
    L.push(
      result.whitelist.rejectedSample
        .map(function (r) {
          return code(r.name);
        })
        .join(', ')
    );
    L.push('');
  }

  // --- Appendix: everything that is the same in every report ---------------
  appendAppendix(L, result, t);
  appendMethodAndCaveats(L, t);
  return L.join('\n');
}

/** The two or three facts that justify the recommendation. */
function conclusionEvidence(result, t) {
  const out = [];
  const bc = (result.candidates || []).find(function (c) {
    return c.name === result.best.name;
  });
  if (!bc) return out;
  const ver = bc.verified || {};
  out.push(t(ver.ok && ver.anchored ? 'conclusion.bullet.genuine' : 'conclusion.bullet.forged'));
  const f = bc.forward || {};
  if (f.identityMatch === true) out.push(t('conclusion.bullet.identical'));
  else if (f.attempted) out.push(t('conclusion.bullet.differs'));
  if (bc.stability) {
    out.push(
      t(bc.stability.ok === bc.stability.attempts ? 'conclusion.bullet.stable' : 'conclusion.bullet.unstable', {
        ok: bc.stability.ok,
        attempts: bc.stability.attempts
      })
    );
  }
  if (result.masking) {
    // Deliberately the short verdict label, not the headline: the headline is printed in
    // full in the masking section immediately below.
    out.push(
      t(result.masking.masking ? 'conclusion.bullet.masking' : 'conclusion.bullet.maskingNone', {
        verdict: t('verdict.' + result.masking.verdict)
      })
    );
  }
  return out;
}

function appendAppendix(L, result, t) {
  const c = result.controls || {};
  const wl = result.whitelist || {};
  L.push('## ' + t('appendix.heading'));
  L.push('');
  L.push('### ' + t('identity.heading'));
  L.push('');
  L.push('| ' + t('identity.probe') + ' | ' + t('identity.handshake') + ' | ' + t('identity.leafCn') + ' | ' + t('identity.anchored') + ' |');
  L.push('| --- | --- | --- | --- |');
  L.push(
    '| ' + t('identity.noSni') +
    ' | ' + t(c.noSni && c.noSni.ok ? 'identity.ok' : 'identity.failed') +
    ' | ' + v(c.noSni && c.noSni.leafCn, DASH) +
    ' | ' + (c.noSni ? t(c.noSni.anchored ? 'misc.yes' : 'misc.no') : DASH) + ' |'
  );
  L.push(
    '| ' + code(v(c.strictName && c.strictName.name, 'invalid2.invalid')) +
    ' | ' + t(c.strictName && c.strictName.ok ? 'identity.accepted' : 'identity.rejected') +
    ' | ' + v(c.strictName && c.strictName.leafCn, DASH) +
    ' | ' + DASH + ' |'
  );
  L.push(
    '| ' + t('identity.randomName') +
    ' | ' + t(c.randomName && c.randomName.ok ? 'identity.accepted' : 'identity.rejected') +
    ' | ' + v(c.randomName && c.randomName.leafCn, DASH) +
    ' | ' + DASH + ' |'
  );
  L.push('');
  L.push('| ' + t('identity.property') + ' | ' + t('table.value') + ' |');
  L.push('| --- | --- |');
  L.push('| ' + t('identity.namesTested') + ' | ' + wl.tested + ' |');
  L.push('| ' + t('identity.namesAccepted') + ' | ' + wl.accepted + ' |');
  L.push('| ' + t('identity.distinctCerts') + ' | ' + v(wl.distinctIdentities) + ' |');
  L.push('| ' + t('identity.generic') + ' | ' + t(wl.genericIdentity ? 'misc.yes' : 'misc.no') + ' |');
  L.push('| ' + t('identity.arbitrary') + ' | ' + t(wl.randomNameAccepted ? 'misc.yes' : 'misc.no') + ' |');
  L.push('| ' + t('identity.strictCompatible') + ' | ' + t(wl.realitlscannerCompatible ? 'misc.yes' : 'misc.no') + ' |');
  L.push('');
  appendPerNameDetail(L, result, t);
}

function appendPerNameDetail(L, result, t) {
  L.push('### ' + t('appendix.detail'));
  L.push('');
  const rows = (result.candidates || []).filter(function (x) {
    return x.stability;
  });
  if (!rows.length) {
    L.push(t('appendix.noDeep', { code: code('--no-deep') }));
    L.push('');
    return;
  }
  for (let i = 0; i < rows.length; i++) {
    const x = rows[i];
    L.push('#### ' + (i + 1) + '. ' + code(x.name) + ' ' + DASH + ' ' + x.score + '/100 (' + gradeWord(t, x.grade) + ')');
    L.push('');
    if (x.scoreComponents && x.scoreComponents.length) {
      L.push('| ' + t('masking.evidenceDetail') + ' | ' + t('masking.evidenceWeight') + ' |');
      L.push('| --- | --- |');
      for (const comp of x.scoreComponents) {
        L.push('| ' + renderMsg(t, comp.reason, deps(t)) + ' | ' + (comp.points > 0 ? '+' : '') + comp.points + ' |');
      }
      L.push('');
    }
    const leaf = x.leaf;
    if (leaf) {
      L.push('| ' + t('table.field') + ' | ' + t('table.value') + ' |');
      L.push('| --- | --- |');
      L.push('| Subject CN | ' + code(v(leaf.cn)) + ' |');
      L.push('| Issuer CN | ' + code(v(leaf.issuerCn)) + ' |');
      L.push('| Valid from | ' + v(leaf.validFrom) + ' |');
      L.push('| Valid to | ' + v(leaf.validTo) + ' |');
      L.push('| SHA-256 | ' + code(v(shortFp(leaf.fingerprint256), '') + '\u2026') + ' |');
      if (x.reference && x.reference.leafFingerprint256) {
        const same = leaf.fingerprint256 === x.reference.leafFingerprint256;
        L.push('| ' + t('compare.leaf') + ' | ' + t(same ? 'compare.identical' : 'compare.differ') + ' |');
      }
      L.push('');
    }
    appendComparison(L, x, t);
    if (x.forward && x.forward.assets && x.forward.assets.length) {
      L.push('| ' + t('assets.asset') + ' | ' + t('compare.throughNode') + ' | ' + t('compare.realSite') + ' | ' + t('assets.identical') + ' |');
      L.push('| --- | --- | --- | --- |');
      for (const a of x.forward.assets) {
        L.push(
          '| ' + code(a.path) +
          ' | ' + (a.via.error ? a.via.error : a.via.bytes + ' B') +
          ' | ' + (a.direct.error ? a.direct.error : a.direct.bytes + ' B') +
          ' | ' + t(a.identical ? 'misc.yes' : 'misc.no') + ' |'
        );
      }
      L.push('');
    }
    if (x.stability) {
      L.push(
        t('stability.line', {
          ok: x.stability.ok,
          attempts: x.stability.attempts,
          determinism: t(
            x.stability.attempts > 0
              ? x.stability.deterministic
                ? 'stability.deterministic'
                : 'stability.varied'
              : 'stability.unknown'
          ),
          min: v(x.stability.latencyMs.min),
          median: v(x.stability.latencyMs.median),
          max: v(x.stability.latencyMs.max)
        })
      );
      L.push('');
    }
    if (x.forward && x.forward.differences && x.forward.differences.length) {
      L.push(t('differences.heading') + ':');
      L.push('');
      for (const d of renderList(t, x.forward.differences, deps(t))) L.push('- ' + d);
      L.push('');
    }
  }
}

/**
 * One table that puts the node and the real site side by side, instead of two paragraphs
 * the reader has to diff by eye.
 */
function appendComparison(L, x, t) {
  const f = x.forward;
  if (!f || !f.attempted) return;
  L.push('**' + t('compare.heading') + '**' + (x.reference && x.reference.address ? ' ' + DASH + ' ' + t('compare.referenceAddress') + ': ' + code(x.reference.address) : ''));
  L.push('');
  if (f.error) {
    L.push('- ' + t('forward.failed') + ': ' + f.error);
    L.push('');
    return;
  }
  const vd = f.verdicts || {};
  const word = function (k) {
    return t('compare.' + (k || 'differ'));
  };
  L.push('| ' + t('compare.check') + ' | ' + t('compare.throughNode') + ' | ' + t('compare.realSite') + ' | ' + t('compare.result') + ' |');
  L.push('| --- | --- | --- | --- |');
  if (f.via && f.direct) {
    L.push('| ' + t('compare.status') + ' | ' + f.via.status + ' | ' + f.direct.status + ' | ' + word(vd.status) + ' |');
    L.push('| ' + t('compare.bytes') + ' | ' + f.via.bytes + ' B | ' + f.direct.bytes + ' B | ' + word(vd.bytes) + ' |');
    L.push('| ' + t('compare.bodyHash') + ' | ' + shortHash(f.via.bodyHash) + ' | ' + shortHash(f.direct.bodyHash) + ' | ' + word(vd.bodyHash) + ' |');
    L.push('| ' + t('compare.timing') + ' | ' + v(f.via.ttfbMs) + ' ' + t('unit.ms') + ' | ' + v(f.direct.ttfbMs) + ' ' + t('unit.ms') + ' | ' + DASH + ' |');
    L.push('| ' + t('compare.hopCount') + ' | ' + hopCount(f.via.hops) + ' | ' + hopCount(f.direct.hops) + ' | ' + DASH + ' |');
    if (f.leafFingerprint256 || (x.reference && x.reference.leafFingerprint256)) {
      L.push('| ' + t('compare.leaf') + ' | ' + shortHash(f.leafFingerprint256) + ' | ' + shortHash(x.reference && x.reference.leafFingerprint256) + ' | ' + word(vd.leafFingerprint) + ' |');
    }
  }
  L.push('');
}

function appendMethodAndCaveats(L, t) {
  L.push('## ' + t('method.heading'));
  L.push('');
  L.push('1. ' + t('method.step1'));
  L.push('2. ' + t('method.step2'));
  L.push('3. ' + t('method.step3'));
  L.push('4. ' + t('method.step4', { code: code('Host') }));
  L.push('');
  L.push(t('method.controls', { code: code('invalid2.invalid') }));
  L.push('');
  L.push('## ' + t('caveats.heading'));
  L.push('');
  L.push('- ' + t('caveat.chain'));
  L.push('- ' + t('caveat.sample'));
  L.push('- ' + t('caveat.personalised', { code: code('--assets') }));
  L.push('- ' + t('caveat.vantage'));
  L.push('');
}

export function render(result, format, t, options) {
  if (format === 'json') return JSON.stringify(result, null, 2);
  if (format === 'text') return renderText(result, t, options);
  return renderMarkdown(result, t);
}

export function defaultOutPath(result, format, locale) {
  const host = (result.node ? result.node.address : 'report').replace(/[:]/g, '_');
  const suffix = locale && locale !== DEFAULT_LOCALE ? '.' + locale : '';
  return 'sni-recon-' + host + suffix + '.' + (format === 'json' ? 'json' : 'md');
}

