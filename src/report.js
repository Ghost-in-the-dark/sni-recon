// Report renderers: Markdown, plain text and JSON.
// Pure functions over the analysis object, so output is reproducible and diffable.
import { pad, padL, clip, round, shortFp } from './util.js';

export const VERSION = '1.0.0';

const FENCE = String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96);
const TICK = String.fromCharCode(96);

function v(x, fallback) {
  return x === null || x === undefined || x === '' ? (fallback === undefined ? 'n/a' : fallback) : x;
}

function yn(b) {
  return b ? 'yes' : 'no';
}

function code(s) {
  return TICK + s + TICK;
}

function certVerdict(c) {
  const ver = c && c.verified;
  if (!ver) return 'not inspected';
  if (ver.ok) return 'genuine (chain verified)';
  if (!ver.anchored) return 'lookalike (not publicly trusted)';
  return 'chain invalid';
}

function forwardVerdict(c) {
  const f = c && c.forward;
  if (!f || !f.attempted) return '\u2014';
  if (f.error) return 'failed';
  if (f.identityMatch === true) return 'identical';
  if (f.comparable) return 'comparable';
  return 'differs';
}

function summaryLine(result) {
  if (!result.reachable) return 'Node did not complete a TLS handshake.';
  if (!result.best) return 'No accepted candidate names found.';
  return 'Best cover: ' + result.best.name + ' (' + result.best.score + '/100, ' + result.best.grade + ').';
}

export function renderMarkdown(result) {
  if (result.nodes) return result.nodes.map(renderMarkdown).join('\n\n---\n\n');
  const L = [];
  const n = result.node;
  L.push('# SNI cover analysis \u2014 ' + n.address + ':' + n.port);
  L.push('');
  L.push('Generated ' + v(result.finishedAt, result.startedAt) + ' \u00b7 sni-recon v' + VERSION);
  L.push('');
  L.push('> ' + summaryLine(result));
  L.push('');

  if (!result.reachable) {
    L.push('## Result');
    L.push('');
    L.push('No TLS handshake completed, with or without SNI.');
    L.push('');
    L.push(result.summary && result.summary.message ? result.summary.message : '');
    L.push('');
    return L.join('\n');
  }

  // Verdict
  L.push('## Verdict');
  L.push('');
  if (result.best) {
    const bc = (result.candidates || []).find(function (c) {
      return c.name === result.best.name;
    });
    L.push('| Field | Value |');
    L.push('| --- | --- |');
    L.push('| Recommended SNI | ' + code(result.best.name) + ' |');
    L.push('| Score | ' + result.best.score + ' / 100 (' + result.best.grade + ') |');
    if (bc && bc.stability) L.push('| Handshake success | ' + bc.stability.ok + '/' + bc.stability.attempts + ' |');
    if (bc && bc.stability && bc.stability.latencyMs.median != null) L.push('| Median handshake latency | ' + bc.stability.latencyMs.median + ' ms |');
    if (bc && bc.validityDaysLeft != null) L.push('| Certificate valid for | ' + bc.validityDaysLeft + ' days |');
    L.push('| Certificate | ' + certVerdict(bc) + ' |');
    L.push('| Forwarding | ' + forwardVerdict(bc) + ' |');
    L.push('');
    L.push('### Configuration');
    L.push('');
    L.push(FENCE + 'json');
    L.push('"serverNames": [' + JSON.stringify(result.best.name) + '],');
    L.push('"dest": ' + JSON.stringify(result.best.dest));
    L.push(FENCE);
    L.push('');
    L.push('Keep ' + code('dest') + ' as a hostname rather than a literal IP so the node resolves it itself. The same name must be present in the client configuration.');
    L.push('');
  } else {
    L.push('No usable cover name was found on this node.');
    L.push('');
  }

  // Masking
  const m = result.masking;
  if (m) {
    L.push('## Hoster-level domain masking');
    L.push('');
    L.push('**' + (m.masking ? 'Masking detected' : m.verdict === 'genuine-front' ? 'No masking detected' : 'Inconclusive') + '** \u2014 ' + m.headline);
    L.push('');
    L.push('| Field | Value |');
    L.push('| --- | --- |');
    L.push('| Verdict | ' + code(m.verdict) + ' |');
    L.push('| Method | ' + code(m.method) + ' |');
    L.push('| Confidence | ' + m.confidence + ' |');
    L.push('| Signal weight | ' + m.weight + ' |');
    if (m.nodeHoster) {
      L.push('| Node operator | ' + v(m.nodeHoster.description) + ' |');
      L.push('| Datacenter address | ' + yn(m.nodeHoster.hosting) + ' |');
    }
    if (m.referenceHoster) L.push('| Real service operator | ' + v(m.referenceHoster.description) + ' |');
    if (m.sameOperator !== null && m.sameOperator !== undefined) L.push('| Same operator | ' + yn(m.sameOperator) + ' |');
    L.push('');
    if (m.evidence && m.evidence.length) {
      L.push('| Evidence | Weight | Detail |');
      L.push('| --- | --- | --- |');
      for (const e of m.evidence) {
        L.push('| ' + code(e.signal) + ' | ' + (e.weight > 0 ? '+' : '') + e.weight + ' | ' + e.detail + ' |');
      }
      L.push('');
    }
  }

  // Node identity
  const c = result.controls || {};
  const wl = result.whitelist || {};
  L.push('## Node identity');
  L.push('');
  L.push('| Probe | Handshake | Certificate CN | Anchored |');
  L.push('| --- | --- | --- | --- |');
  L.push('| no SNI | ' + (c.noSni && c.noSni.ok ? 'ok' : 'failed') + ' | ' + v(c.noSni && c.noSni.leafCn, '\u2014') + ' | ' + (c.noSni ? yn(c.noSni.anchored) : '\u2014') + ' |');
  L.push('| ' + code(v(c.strictName && c.strictName.name, 'invalid2.invalid')) + ' | ' + (c.strictName && c.strictName.ok ? 'accepted' : 'rejected') + ' | ' + v(c.strictName && c.strictName.leafCn, '\u2014') + ' | \u2014 |');
  L.push('| random .invalid name | ' + (c.randomName && c.randomName.ok ? 'accepted' : 'rejected') + ' | ' + v(c.randomName && c.randomName.leafCn, '\u2014') + ' | \u2014 |');
  L.push('');
  L.push('| Property | Value |');
  L.push('| --- | --- |');
  L.push('| Names tested | ' + wl.tested + ' |');
  L.push('| Names accepted | ' + wl.accepted + ' |');
  L.push('| Distinct certificates seen | ' + v(wl.distinctIdentities) + ' |');
  L.push('| Single certificate for every SNI | ' + yn(wl.genericIdentity) + ' |');
  L.push('| Accepts arbitrary undeclared names | ' + yn(wl.randomNameAccepted) + ' |');
  L.push('| Compatible with a strict invalid2.invalid scan | ' + yn(wl.realitlscannerCompatible) + ' |');
  L.push('');

  // Ranking
  L.push('## Candidate ranking');
  L.push('');
  L.push('| # | Name | Group | Score | Grade | Certificate | Forward | Median ms |');
  L.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
  const rows = result.candidates || [];
  for (let i = 0; i < rows.length; i++) {
    const x = rows[i];
    const ms = x.stability && x.stability.latencyMs ? x.stability.latencyMs.median : null;
    L.push('| ' + (i + 1) + ' | ' + code(x.name) + ' | ' + v(x.group) + ' | ' + v(x.score) + ' | ' + v(x.grade) + ' | ' + certVerdict(x) + ' | ' + forwardVerdict(x) + ' | ' + v(ms) + ' |');
  }
  L.push('');

  // Detail
  L.push('## Detail');
  L.push('');
  const deep = rows.filter(function (x) {
    return x.stability;
  });
  if (!deep.length) {
    L.push('Run without ' + code('--no-deep') + ' to collect certificate, latency and forward-verification detail.');
    L.push('');
  }
  for (let i = 0; i < deep.length; i++) {
    const x = deep[i];
    L.push('### ' + (i + 1) + '. ' + code(x.name) + ' \u2014 ' + x.score + '/100 (' + x.grade + ')');
    L.push('');
    if (x.scoreComponents && x.scoreComponents.length) {
      L.push('| Score component | Points |');
      L.push('| --- | --- |');
      for (const comp of x.scoreComponents) L.push('| ' + comp.reason + ' | ' + (comp.points > 0 ? '+' : '') + comp.points + ' |');
      L.push('');
    }
    const leaf = x.leaf;
    if (leaf) {
      L.push('| Certificate | Value |');
      L.push('| --- | --- |');
      L.push('| Subject CN | ' + code(v(leaf.cn)) + ' |');
      L.push('| Issuer CN | ' + code(v(leaf.issuerCn)) + ' |');
      L.push('| Valid from | ' + v(leaf.validFrom) + ' |');
      L.push('| Valid to | ' + v(leaf.validTo) + ' |');
      L.push('| SHA-256 | ' + code(v(shortFp(leaf.fingerprint256)) + '\u2026') + ' |');
      if (x.reference && x.reference.leafFingerprint256) {
        L.push('| Matches real site certificate | ' + (leaf.fingerprint256 === x.reference.leafFingerprint256 ? 'yes' : '**no**') + ' |');
      }
      L.push('');
    }
    if (x.forward && x.forward.checks) {
      L.push('Forward verification against ' + code(v(x.reference && x.reference.address)) + ':');
      L.push('');
      L.push('| Check | Result |');
      L.push('| --- | --- |');
      for (const k of Object.keys(x.forward.checks)) L.push('| ' + k + ' | ' + x.forward.checks[k] + ' |');
      if (x.forward.via) L.push('| through node | HTTP ' + x.forward.via.status + ', ' + x.forward.via.bytes + ' bytes, ' + v(x.forward.via.ttfbMs) + ' ms |');
      if (x.forward.direct) L.push('| direct | HTTP ' + x.forward.direct.status + ', ' + x.forward.direct.bytes + ' bytes, ' + v(x.forward.direct.ttfbMs) + ' ms |');
      L.push('');
    }
    if (x.forward && x.forward.assets && x.forward.assets.length) {
      L.push('| Asset | Through node | Direct | Identical |');
      L.push('| --- | --- | --- | --- |');
      for (const a of x.forward.assets) {
        L.push('| ' + code(a.path) + ' | ' + (a.via.error ? a.via.error : a.via.bytes + ' B') + ' | ' + (a.direct.error ? a.direct.error : a.direct.bytes + ' B') + ' | ' + (a.identical ? 'yes' : 'no') + ' |');
      }
      L.push('');
    }
    if (x.stability) {
      L.push('Stability: ' + x.stability.ok + '/' + x.stability.attempts + ' handshakes, ' + (x.stability.deterministic ? 'identical certificate each time' : 'certificate varied') + ', latency min/median/max ' + v(x.stability.latencyMs.min) + '/' + v(x.stability.latencyMs.median) + '/' + v(x.stability.latencyMs.max) + ' ms.');
      L.push('');
    }
    if (x.forward && x.forward.differences && x.forward.differences.length) {
      L.push('Differences from the real site:');
      L.push('');
      for (const d of x.forward.differences) L.push('- ' + d);
      L.push('');
    }
  }

  if (result.summary && result.summary.notes && result.summary.notes.length) {
    L.push('## Notes');
    L.push('');
    for (const note of result.summary.notes) L.push('- ' + note);
    L.push('');
  }
  if (wl.rejectedSample && wl.rejectedSample.length) {
    L.push('## Names rejected by the node');
    L.push('');
    L.push(wl.rejectedSample.map(function (r) { return code(r.name); }).join(', '));
    L.push('');
  }

  L.push('## Method');
  L.push('');
  L.push('1. **Whitelist mapping** \u2014 raw TLS handshakes with each candidate as SNI, recording only whether the handshake completes.');
  L.push('2. **Identity check** \u2014 the presented chain is verified **offline** against Node\u2019s bundled trust store: validity windows, signature links, and a trusted anchor.');
  L.push('3. **Operator identification** \u2014 the node address and the real service address are resolved to an ASN and organisation.');
  L.push('4. **Forward verification** \u2014 one request goes to the node\u2019s address with the candidate as both SNI and ' + code('Host') + ', and the same request to the real site\u2019s own address; status, length and body SHA-256 are compared.');
  L.push('');
  L.push('Control probes (no SNI, ' + code('invalid2.invalid') + ', a random undeclared name) establish what the node does with names it does not own.');
  L.push('');
  L.push('## Caveats');
  L.push('');
  L.push('- A verified chain proves the node presents the genuine certificate, **not** that it is the genuine operator. A node that transparently forwards to the real site is indistinguishable here from the real site itself \u2014 by design.');
  L.push('- Sample sizes are small. Scores rank names on one node against each other; they are not absolute safety guarantees.');
  L.push('- Landing pages are often personalised. Static asset hashes are stronger evidence; add them with ' + code('--assets') + '.');
  L.push('- Reachability from this vantage point says nothing about blocking from the client\u2019s network.');
  L.push('');
  return L.join('\n');
}

export function renderText(result) {
  if (result.nodes) return result.nodes.map(renderText).join('\n');
  const out = [];
  const n = result.node;
  out.push('');
  out.push('sni-recon \u2014 ' + n.address + ':' + n.port);
  out.push('='.repeat(64));
  if (!result.reachable) {
    out.push('UNREACHABLE: ' + (result.summary ? result.summary.message : ''));
    out.push('');
    return out.join('\n');
  }
  const wl = result.whitelist || {};
  const m = result.masking;
  if (m) {
    out.push((m.masking ? '[!] MASKING DETECTED' : '[ok] no masking detected') + '  (' + m.method + ', confidence ' + m.confidence + ')');
    out.push('    ' + m.headline);
  }
  if (result.hoster && result.hoster.ok) {
    out.push('operator: ' + [result.hoster.asn, result.hoster.asName || result.hoster.org].filter(Boolean).join(' ') + (result.hoster.city ? ' \u00b7 ' + result.hoster.city + ', ' + result.hoster.countryCode : '') + (result.hoster.hosting ? '  [datacenter]' : ''));
  }
  out.push('names tested ' + wl.tested + ' \u00b7 accepted ' + wl.accepted + ' \u00b7 distinct certificates ' + v(wl.distinctIdentities));
  out.push('');
  if (result.best) {
    out.push('RECOMMENDED  ' + result.best.name + '   (score ' + result.best.score + '/100, ' + result.best.grade + ')');
    out.push('  serverNames: ' + JSON.stringify(result.best.name));
    out.push('  dest:        ' + result.best.dest);
    out.push('');
  }
  out.push(pad('#', 4) + pad('name', 30) + padL('score', 6) + '  ' + pad('grade', 10) + pad('certificate', 32) + pad('forward', 12) + padL('ms', 7));
  out.push('-'.repeat(101));
  const rows = result.candidates || [];
  for (let i = 0; i < rows.length; i++) {
    const x = rows[i];
    const ms = x.stability && x.stability.latencyMs ? x.stability.latencyMs.median : null;
    out.push(pad(i + 1, 4) + pad(clip(x.name, 29), 30) + padL(v(x.score), 6) + '  ' + pad(v(x.grade), 10) + pad(clip(certVerdict(x), 31), 32) + pad(forwardVerdict(x), 12) + padL(v(ms), 7));
  }
  out.push('');
  if (result.summary && result.summary.notes) {
    for (const note of result.summary.notes) out.push('note: ' + note);
  }
  out.push('');
  return out.join('\n');
}

export function render(result, format) {
  if (format === 'json') return JSON.stringify(result, null, 2);
  if (format === 'text') return renderText(result);
  return renderMarkdown(result);
}

export function defaultOutPath(result, format) {
  const host = (result.node ? result.node.address : 'report').replace(/[:]/g, '_');
  return 'sni-recon-' + host + '.' + (format === 'json' ? 'json' : 'md');
}
