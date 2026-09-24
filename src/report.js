// Report renderers: Markdown, plain text and JSON.
//
// Pure functions over the analysis object and a translator, so output is reproducible and
// diffable, and the same scan can be re-rendered in another locale without re-running it.
//
// Layout principle: the reader is told the ANSWER first. A conclusion block with the
// recommended name and its configuration sits at the top; the evidence that supports it
// sits directly under the same heading; the methodology, caveats and per-name appendix
// are pushed to the end, because they are the same in every report and are read once.
import { pad, padL, clip, shortFp } from './util.js';
import { localizer, DEFAULT_LOCALE } from './i18n/index.js';
import { renderMsg, renderList } from './messages.js';

export const VERSION = '1.1.0';

const FENCE = String.fromCharCode(96).repeat(3);
const TICK = String.fromCharCode(96);

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

function forwardVerdict(c, t) {
  const f = c && c.forward;
  if (!f || !f.attempted) return '\u2014';
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
      L.push('| ' + t('verdict.medianLatency') + ' | ' + bc.stability.latencyMs.median + ' ms |');
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
    L.push('**' + tag + '** — ' + renderMsg(t, m.headline, deps(t)));
    L.push('');
    L.push('| ' + t('table.field') + ' | ' + t('table.value') + ' |');
    L.push('| --- | --- |');
    L.push('| ' + t('masking.verdict') + ' | ' + code(cap(t('verdict.' + m.verdict))) + ' |');
    L.push('| ' + t('masking.method') + ' | ' + code(cap(t('method.' + m.method))) + ' |');
    L.push('| ' + t('masking.confidence') + ' | ' + t('confidence.' + m.confidence) + ' |');
    L.push('| ' + t('masking.weight') + ' | ' + m.weight + ' |');
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
    ' | ' + v(c.noSni && c.noSni.leafCn, '\u2014') +
    ' | ' + (c.noSni ? t(c.noSni.anchored ? 'misc.yes' : 'misc.no') : '\u2014') + ' |'
  );
  L.push(
    '| ' + code(v(c.strictName && c.strictName.name, 'invalid2.invalid')) +
    ' | ' + t(c.strictName && c.strictName.ok ? 'identity.accepted' : 'identity.rejected') +
    ' | ' + v(c.strictName && c.strictName.leafCn, '\u2014') +
    ' | \u2014 |'
  );
  L.push(
    '| ' + t('identity.randomName') +
    ' | ' + t(c.randomName && c.randomName.ok ? 'identity.accepted' : 'identity.rejected') +
    ' | ' + v(c.randomName && c.randomName.leafCn, '\u2014') +
    ' | \u2014 |'
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
    L.push('#### ' + (i + 1) + '. ' + code(x.name) + ' \u2014 ' + x.score + '/100 (' + gradeWord(t, x.grade) + ')');
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
          determinism: t(x.stability.deterministic ? 'stability.deterministic' : 'stability.varied'),
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
  L.push('**' + t('compare.heading') + '**' + (x.reference && x.reference.address ? ' \u2014 ' + t('compare.referenceAddress') + ': ' + code(x.reference.address) : ''));
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
    L.push('| ' + t('compare.timing') + ' | ' + v(f.via.ttfbMs) + ' ms | ' + v(f.direct.ttfbMs) + ' ms | \u2014 |');
    L.push('| ' + t('compare.hopCount') + ' | ' + v(f.via.hops, 0) + ' | ' + v(f.direct.hops, 0) + ' | \u2014 |');
    if (f.leafFingerprint256 || (x.reference && x.reference.leafFingerprint256)) {
      L.push('| ' + t('compare.leaf') + ' | ' + shortHash(f.leafFingerprint256) + ' | ' + shortHash(x.reference && x.reference.leafFingerprint256) + ' | ' + word(vd.leafFingerprint) + ' |');
    }
  }
  L.push('');
}

function shortHash(h) {
  if (!h) return '\u2014';
  const compact = String(h).replace(/:/g, '');
  return code(compact.slice(0, 12).toUpperCase() + '\u2026');
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

// ---------------------------------------------------------------------------
// Plain text
// ---------------------------------------------------------------------------

export function renderText(result, tIn) {
  const t = translator(tIn);
  if (result.nodes) {
    return result.nodes
      .map(function (r) {
        return renderText(r, t);
      })
      .join('\n');
  }
  const out = [];
  const n = result.node;
  out.push('');
  out.push('sni-recon \u2014 ' + n.address + ':' + n.port);
  out.push('='.repeat(64));
  if (!result.reachable) {
    out.push(t('result.noHandshake') + ' ' + renderMsg(t, result.summary && result.summary.message, deps(t)));
    out.push('');
    return out.join('\n');
  }
  const wl = result.whitelist || {};
  const m = result.masking;
  if (m) {
    const tag = m.masking ? '[!] ' + t('masking.detected') : m.verdict === 'genuine-front' ? '[ok] ' + t('masking.notDetected') : '[?] ' + t('masking.inconclusive');
    out.push(tag + '  (' + t('method.' + m.method) + ', ' + t('confidence.' + m.confidence) + ')');
    out.push('    ' + renderMsg(t, m.headline, deps(t)));
  }
  if (result.hoster && result.hoster.ok) {
    out.push(
      t('masking.nodeOperator') + ': ' +
        [result.hoster.asn, result.hoster.asName || result.hoster.org].filter(Boolean).join(' ') +
        (result.hoster.city ? ' \u00b7 ' + result.hoster.city + ', ' + result.hoster.countryCode : '') +
        (result.hoster.hosting ? '  [' + t('tui.datacenter') + ']' : '')
    );
  }
  out.push(t('identity.namesTested') + ' ' + wl.tested + ' \u00b7 ' + t('identity.namesAccepted') + ' ' + wl.accepted + ' \u00b7 ' + t('identity.distinctCerts') + ' ' + v(wl.distinctIdentities));
  out.push('');
  if (result.best) {
    const weak = result.best.grade === 'poor';
    out.push(
      plain(
        t(weak ? 'conclusion.bestWeak' : 'conclusion.best', {
          name: result.best.name,
          score: result.best.score,
          grade: gradeWord(t, result.best.grade)
        })
      )
    );
    out.push('  serverNames: ' + JSON.stringify(result.best.name));
    out.push('  dest:        ' + result.best.dest);
    out.push('');
  } else {
    out.push(t('conclusion.noName'));
    out.push('');
  }
  const nameWidth = 30;
  out.push(pad(t('ranking.rank'), 4) + pad(t('ranking.name'), nameWidth) + padL(t('ranking.score'), 6) + '  ' + pad(t('ranking.grade'), 10) + pad(t('ranking.certificate'), 32) + pad(t('ranking.forward'), 12) + padL(t('ranking.medianMs'), 8));
  out.push('-'.repeat(105));
  const rows = result.candidates || [];
  for (let i = 0; i < rows.length; i++) {
    const x = rows[i];
    const ms = x.stability && x.stability.latencyMs ? x.stability.latencyMs.median : null;
    out.push(
      pad(i + 1, 4) +
        pad(clip(x.name, nameWidth - 1), nameWidth) +
        padL(v(x.score), 6) + '  ' +
        pad(clip(gradeWord(t, x.grade), 9), 10) +
        pad(clip(certVerdict(x, t), 31), 32) +
        pad(clip(forwardVerdict(x, t), 11), 12) +
        padL(v(ms), 8)
    );
  }
  out.push('');
  for (const note of renderList(t, result.summary && result.summary.notes, deps(t))) out.push('note: ' + note);
  out.push('');
  return out.join('\n');
}

export function render(result, format, t) {
  if (format === 'json') return JSON.stringify(result, null, 2);
  if (format === 'text') return renderText(result, t);
  return renderMarkdown(result, t);
}

export function defaultOutPath(result, format, locale) {
  const host = (result.node ? result.node.address : 'report').replace(/[:]/g, '_');
  const suffix = locale && locale !== DEFAULT_LOCALE ? '.' + locale : '';
  return 'sni-recon-' + host + suffix + '.' + (format === 'json' ? 'json' : 'md');
}
