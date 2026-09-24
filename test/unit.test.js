// Node test-runner suite over the pure parts of the tool: scoring, hoster comparison,
// certificate verification, localisation, redaction and report rendering.
//
// Hoster fixtures here are fictional on purpose: a test that hard-codes a real provider's
// name, ASN and city would publish that infrastructure with the repository, and would break
// whenever the fixture moved.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scoreCandidate, gradeOf } from '../src/analyze.js';
import { sameOperator, describeHoster } from '../src/hoster.js';
import { evaluateMasking, METHOD } from '../src/masking.js';
import { renderMarkdown, renderText, render, defaultOutPath, VERSION } from '../src/report.js';
import { dedupeNames, candidatesFor, FAST_CANDIDATES, REGIONAL, groupOf } from '../src/candidates.js';
import { parseSans, cnOf, normDn, trustedRoots, verifyChain, x509 } from '../src/cert.js';
import { median, isBenchmarkIp, isIp, clip } from '../src/util.js';
import { localizer, localeFromEnv, normalizeLocale, CATALOGUES, LOCALES, DEFAULT_LOCALE, LOCALE_NAMES } from '../src/i18n/index.js';
import { msg, isMsg, renderMsg, renderList } from '../src/messages.js';
import { redactOperatorDetails, REDACTED } from '../src/redact.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// --- fixtures --------------------------------------------------------------

const NODE_HOSTER = { ok: true, asn: 'AS64500', asName: 'EXAMPLE HOSTING LTD', org: 'EXAMPLE HOSTING LTD', city: 'Example City', countryCode: 'ZZ', hosting: true };
const REF_HOSTER = { ok: true, asn: 'AS64501', asName: 'EXAMPLE CDN INC', org: 'EXAMPLE CDN INC', countryCode: 'ZZ', hosting: true };

function sampleResult() {
  return {
    node: { address: '203.0.113.7', port: 443 },
    startedAt: '2026-01-01T00:00:00Z',
    finishedAt: '2026-01-01T00:01:00Z',
    reachable: true,
    controls: { noSni: { ok: false, error: 'ECONNRESET' }, strictName: { ok: false, name: 'invalid2.invalid' }, randomName: { ok: true, name: 'x.invalid' } },
    whitelist: {
      tested: 50,
      accepted: 1,
      acceptedNames: ['www.example.com'],
      rejectedSample: [{ name: 'www.other.com' }],
      distinctIdentities: 1,
      genericIdentity: false,
      randomNameAccepted: true,
      realitlscannerCompatible: false
    },
    candidates: [
      {
        name: 'www.example.com',
        group: 'infra',
        score: 88,
        grade: 'excellent',
        leaf: { cn: 'www.example.com', issuerCn: 'Example CA', validFrom: '2025-01-01', validTo: '2027-01-01', fingerprint256: 'AB:CD:EF:01:23:45:67:89:AA:BB:CC:DD:EE:FF:00:11' },
        verified: { ok: true, anchored: true },
        validityDaysLeft: 300,
        stability: { ok: 5, attempts: 5, deterministic: true, latencyMs: { min: 10, median: 12, max: 20 } },
        forward: {
          attempted: true,
          identityMatch: true,
          comparable: true,
          verdicts: { status: 'match', bytes: 'match', bodyHash: 'identical', leafFingerprint: 'identical' },
          via: { status: 200, bytes: 100, ttfbMs: 30, hops: 0, bodyHash: 'aa11', leafFingerprint256: 'AB:CD' },
          direct: { status: 200, bytes: 100, ttfbMs: 80, hops: 0, bodyHash: 'aa11' },
          differences: []
        },
        reference: { address: '198.51.100.9', leafFingerprint256: 'AB:CD:EF:01:23:45:67:89:AA:BB:CC:DD:EE:FF:00:11' },
        scoreComponents: [{ points: 35, reason: msg('score.certGenuine') }]
      }
    ],
    best: { name: 'www.example.com', score: 88, grade: 'excellent', dest: 'www.example.com:443' },
    masking: {
      masking: false,
      method: 'none',
      confidence: 'high',
      verdict: 'genuine-front',
      headline: msg('masking.headline.genuine-front'),
      weight: -2,
      evidence: [{ signal: 'operator-match', weight: -2, detail: msg('evidence.operator-match', { node: { asn: 'AS64500', asName: 'EXAMPLE HOSTING LTD', city: 'Example City', countryCode: 'ZZ' } }) }],
      sameOperator: true,
      nodeHoster: { description: 'AS64500 EXAMPLE HOSTING LTD', hosting: true },
      referenceHoster: { description: 'AS64501 EXAMPLE CDN INC' }
    },
    summary: { bestName: 'www.example.com', notes: [msg('note.genericIdentity')] }
  };
}

// --- scoring ---------------------------------------------------------------

test('gradeOf maps scores to grades', function () {
  assert.equal(gradeOf(90), 'excellent');
  assert.equal(gradeOf(80), 'excellent');
  assert.equal(gradeOf(65), 'good');
  assert.equal(gradeOf(45), 'fair');
  assert.equal(gradeOf(0), 'poor');
  assert.equal(gradeOf(-20), 'poor');
});

test('gradeOf returns stable identifiers, not translated words', function () {
  // The renderer owns the wording; a translated grade here would break JSON consumers.
  for (const locale of LOCALES) {
    assert.equal(gradeOf(90), 'excellent');
  }
});

test('scoreCandidate rewards a genuine, byte-identical identity', function () {
  const c = {
    name: 'www.example.com',
    verified: { ok: true, anchored: true },
    fingerprint256: 'AA:BB'.repeat(16),
    validityDaysLeft: 300,
    stability: { successRate: 1, deterministic: true },
    forward: { identityMatch: true },
    via: { keyExchange: { name: 'X25519' } }
  };
  const ctx = { referenceFingerprint: c.fingerprint256, referenceGroups: 'X25519' };
  const r = scoreCandidate(c, ctx);
  assert.ok(r.score >= 80, 'expected a high score, got ' + r.score);
  assert.equal(r.grade, 'excellent');
});

test('scoreCandidate penalises a forged identity', function () {
  const c = {
    name: 'www.example.com',
    verified: { ok: false, anchored: false },
    stability: { successRate: 0.4, deterministic: false },
    forward: { attempted: true, error: 'handshake failed' },
    via: { keyExchange: { name: 'P-256' } }
  };
  const r = scoreCandidate(c, { referenceGroups: 'X25519' });
  assert.ok(r.score < 0, 'expected a negative score, got ' + r.score);
  assert.equal(r.grade, 'poor');
});

test('score components carry message keys, not English prose', function () {
  const c = { name: 'a.com', verified: { ok: true, anchored: true }, stability: { successRate: 1, deterministic: true }, forward: { identityMatch: true } };
  const r = scoreCandidate(c, {});
  for (const comp of r.components) {
    assert.ok(isMsg(comp.reason), 'component reason must be a message value');
  }
  assert.match(renderMsg(localizer('ru'), r.components[0].reason), /\p{Script=Cyrillic}/u);
});

// --- hoster ----------------------------------------------------------------

test('sameOperator matches on ASN and on organisation name', function () {
  assert.equal(sameOperator({ ok: true, asn: 'AS1' }, { ok: true, asn: 'AS1' }), true);
  assert.equal(sameOperator({ ok: true, asn: 'AS1' }, { ok: true, asn: 'AS2' }), false);
  assert.equal(sameOperator({ ok: true, asn: 'AS1', org: 'Acme Hosting Ltd' }, { ok: true, org: 'ACME HOSTING' }), true);
  assert.equal(sameOperator({ ok: false }, { ok: true, asn: 'AS1' }), null);
});

test('describeHoster renders a readable summary', function () {
  const s = describeHoster({ ok: true, asn: 'AS64500', asName: 'EXAMPLE HOSTING LTD', city: 'Example City', countryCode: 'ZZ' });
  assert.match(s, /AS64500/);
  assert.match(s, /Example City/);
  assert.equal(describeHoster(null), 'unknown');
});

test('describeHoster survives a redacted record', function () {
  const s = describeHoster({ ok: true, asn: REDACTED, asName: REDACTED, city: REDACTED, countryCode: REDACTED });
  assert.notEqual(s, 'unknown', 'a redacted record still has a label worth showing');
  assert.ok(s.indexOf(REDACTED) !== -1);
});

// --- masking ---------------------------------------------------------------

test('evaluateMasking detects a forged certificate at high confidence', function () {
  const m = evaluateMasking({
    nodeHoster: NODE_HOSTER,
    referenceHoster: REF_HOSTER,
    controls: { randomName: { ok: true, name: 'x.invalid' } },
    candidates: [{ name: 'www.jetbrains.com', verified: { ok: false, anchored: false }, leaf: { issuerCn: 'Fake CA' } }],
    genericIdentity: false
  });
  assert.equal(m.masking, true);
  assert.equal(m.method, METHOD.FORGED);
  assert.equal(m.confidence, 'high');
  assert.ok(m.evidence.length >= 2);
});

test('evaluateMasking records evidence as message values', function () {
  const m = evaluateMasking({
    nodeHoster: NODE_HOSTER,
    referenceHoster: REF_HOSTER,
    controls: { randomName: { ok: false } },
    candidates: [{ name: 'a.com', verified: { ok: false, anchored: false }, leaf: { issuerCn: 'Fake CA' } }],
    genericIdentity: false
  });
  for (const e of m.evidence) assert.ok(isMsg(e.detail), 'detail must be a message value');
  assert.ok(isMsg(m.headline));
  // Rendering the same verdict in two locales must produce two different strings.
  const en = renderMsg(localizer('en'), m.headline);
  const ru = renderMsg(localizer('ru'), m.headline);
  assert.notEqual(en, ru);
  assert.ok(/\p{Script=Cyrillic}/u.test(ru));
});

test('evaluateMasking clears a node that is the genuine service', function () {
  const m = evaluateMasking({
    nodeHoster: { ok: true, asn: 'AS64501', org: 'EXAMPLE CDN INC', hosting: true },
    referenceHoster: { ok: true, asn: 'AS64501', org: 'EXAMPLE CDN INC', hosting: true },
    controls: { randomName: { ok: false }, strictName: { ok: false } },
    candidates: [
      {
        name: 'www.example.com',
        verified: { ok: true, anchored: true },
        fingerprint256: 'AA',
        reference: { ok: true, leafFingerprint256: 'AA', keyExchange: { name: 'X25519' } },
        via: { keyExchange: { name: 'X25519' } },
        forward: { identityMatch: true }
      }
    ],
    genericIdentity: false
  });
  assert.equal(m.masking, false);
  assert.equal(m.verdict, 'genuine-front');
  assert.equal(m.sameOperator, true);
});

test('evaluateMasking still flags a forged node when candidates were never deep-analysed', function () {
  const m = evaluateMasking({
    nodeHoster: NODE_HOSTER,
    referenceHoster: REF_HOSTER,
    controls: { randomName: { ok: true, name: 'x.invalid' } },
    // No stability field: this is what --no-deep produces.
    candidates: [{ name: 'www.jetbrains.com', verified: { ok: false, anchored: false }, leaf: { issuerCn: 'Fake CA' } }],
    genericIdentity: false
  });
  assert.equal(m.masking, true);
  assert.equal(m.method, METHOD.FORGED);
});

// --- localisation ----------------------------------------------------------

test('locales define an identical key set', function () {
  const en = Object.keys(CATALOGUES[DEFAULT_LOCALE]).sort();
  assert.ok(en.length > 200, 'expected a substantial catalogue, got ' + en.length);
  for (const loc of LOCALES) {
    const keys = Object.keys(CATALOGUES[loc]).sort();
    assert.deepEqual(keys, en, 'locale ' + loc + ' key set differs from ' + DEFAULT_LOCALE);
  }
});

test('normalizeLocale accepts POSIX and BCP-47 tags', function () {
  assert.equal(normalizeLocale('ru_RU.UTF-8'), 'ru');
  assert.equal(normalizeLocale('ru-RU'), 'ru');
  assert.equal(normalizeLocale('en_US'), 'en');
  assert.equal(normalizeLocale('ru:en'), 'ru');
  assert.equal(normalizeLocale('C'), null);
  assert.equal(normalizeLocale('POSIX'), null);
  assert.equal(normalizeLocale('de_DE'), null, 'a locale we do not ship must not be claimed');
  assert.equal(normalizeLocale(''), null);
  assert.equal(normalizeLocale(null), null);
});

test('localeFromEnv follows POSIX precedence', function () {
  assert.equal(localeFromEnv({ LANG: 'ru_RU.UTF-8' }), 'ru');
  assert.equal(localeFromEnv({ LANG: 'ru_RU.UTF-8', LC_ALL: 'en_US.UTF-8' }), 'en', 'LC_ALL wins over LANG');
  assert.equal(localeFromEnv({ LANG: 'ru_RU.UTF-8', LC_MESSAGES: 'en_US.UTF-8' }), 'en', 'LC_MESSAGES wins over LANG');
  assert.equal(localeFromEnv({ LANG: 'C', LANGUAGE: 'ru' }), 'ru', 'LANGUAGE is consulted after LANG');
  assert.equal(localeFromEnv({}), DEFAULT_LOCALE);
  assert.equal(localeFromEnv({ LANG: 'C' }), DEFAULT_LOCALE);
});

test('a missing key falls back to the key and unknown locales fall back to English', function () {
  const t = localizer('ru');
  assert.equal(t('this.key.does.not.exist'), 'this.key.does.not.exist');
  const fallback = localizer('de');
  assert.equal(fallback.locale, DEFAULT_LOCALE);
});

test('interpolation substitutes parameters and leaves unknown ones alone', function () {
  const t = localizer('en');
  const s = t('conclusion.best', { name: 'a.com', score: 90, grade: 'excellent' });
  assert.match(s, /a\.com/);
  assert.match(s, /90\/100/);
  assert.equal(t('progress.wrote', { path: '/tmp/x' }), 'wrote /tmp/x');
});

test('message values nest and render in the requested locale', function () {
  const t = localizer('ru');
  const nested = msg('evidence.operator-mismatch', { node: 'AS1 NODE', reference: 'AS2 REF' });
  const out = renderMsg(t, nested);
  assert.ok(out.indexOf('AS1 NODE') !== -1 && out.indexOf('AS2 REF') !== -1);
  assert.ok(/\p{Script=Cyrillic}/u.test(out));
  const outer = msg('conclusion.bullet.masking', { headline: msg('masking.headline.genuine-front') });
  assert.ok(/\p{Script=Cyrillic}/u.test(renderMsg(t, outer)));
  assert.equal(renderList(t, [msg('note.weakCover'), null], {}).length, 1);
});

test('renderMsg tolerates junk without throwing', function () {
  const t = localizer('en');
  assert.equal(renderMsg(t, null), '');
  assert.equal(renderMsg(t, undefined), '');
  assert.equal(renderMsg(t, 'plain'), 'plain');
  assert.equal(isMsg('plain'), false);
  assert.equal(isMsg({ key: 5 }), false);
});
// --- reporting -------------------------------------------------------------

test('renderMarkdown emits a usable report skeleton', function () {
  const result = sampleResult();
  const t = localizer('en');
  const md = renderMarkdown(result, t);
  assert.match(md, /^# SNI cover analysis/);
  assert.match(md, /Recommended SNI/);
  assert.match(md, /"serverNames": \["www\.example\.com"\]/);
  assert.match(md, /Hoster-level domain masking/);
  assert.match(md, /Candidate ranking/);
  assert.ok(md.indexOf(String.fromCharCode(96, 96, 96, 34)) === -1, 'no stray escaped fence');
  const txt = renderText(result, t);
  assert.match(txt, /Recommended SNI/);
  assert.match(JSON.parse(render(result, 'json')).node.address, /203\.0\.113\.7/);
  assert.equal(defaultOutPath(result, 'json'), 'sni-recon-203.0.113.7.json');
  assert.equal(defaultOutPath(result, 'md', 'ru'), 'sni-recon-203.0.113.7.ru.md');
});

test('the conclusion precedes the methodology', function () {
  const md = renderMarkdown(sampleResult(), localizer('en'));
  assert.ok(md.indexOf('## Conclusion') < md.indexOf('## Method'), 'the answer must come first');
  assert.ok(md.indexOf('## Conclusion') < md.indexOf('## Appendix'), 'the appendix must come last');
  assert.ok(md.indexOf('## Candidate ranking') < md.indexOf('## Appendix'));
});

test('the comparison table puts both sides side by side', function () {
  const md = renderMarkdown(sampleResult(), localizer('en'));
  assert.match(md, /Comparison with the real site/);
  assert.match(md, /\| Check \| Through node \| Real site \| Result \|/);
  assert.match(md, /\| HTTP status \| 200 \| 200 \| match \|/);
});

test('a full report renders in Russian without leaking a key', function () {
  const result = sampleResult();
  const ru = renderMarkdown(result, localizer('ru'));
  assert.match(ru, /^# Анализ SNI-маскировки/);
  assert.match(ru, /Рекомендуемый SNI/);
  assert.match(ru, /Заключение/);
  assert.match(ru, /Ранжирование кандидатов/);
  for (const key of Object.keys(CATALOGUES.en)) {
    assert.ok(ru.indexOf(key) === -1, 'raw key leaked into the Russian report: ' + key);
  }
  const txt = renderText(result, localizer('ru'));
  assert.ok(/\p{Script=Cyrillic}/u.test(txt));
  assert.ok(txt.indexOf('Рекомендуемый SNI') !== -1);
});

test('the same result renders differently in two locales', function () {
  const result = sampleResult();
  const en = renderMarkdown(result, localizer('en'));
  const ru = renderMarkdown(result, localizer('ru'));
  assert.notEqual(en, ru);
  // Only the prose differs: the machine-readable measurements must be identical.
  assert.match(en, /www\.example\.com/);
  assert.match(ru, /www\.example\.com/);
  assert.match(en, /88 \/ 100/);
  assert.match(ru, /88 \/ 100/);
});

test('renderMarkdown handles an unreachable node in both locales', function () {
  for (const loc of LOCALES) {
    const md = renderMarkdown(
      {
        node: { address: '203.0.113.9', port: 443 },
        startedAt: '2026-01-01T00:00:00Z',
        reachable: false,
        summary: { message: msg('unreachable.message', { error: 'ECONNREFUSED' }), verdict: 'unreachable' }
      },
      localizer(loc)
    );
    assert.match(md, /ECONNREFUSED/);
  }
});

test('renderMarkdown handles a node that accepts nothing', function () {
  const md = renderMarkdown(
    {
      node: { address: '203.0.113.9', port: 443 },
      startedAt: '2026-01-01T00:00:00Z',
      reachable: true,
      controls: {},
      whitelist: { tested: 10, accepted: 0, rejectedSample: [] },
      candidates: [],
      best: null,
      summary: { verdict: 'no-candidate-accepted', message: msg('noCandidates.message', { tested: 10 }) }
    },
    localizer('en')
  );
  assert.match(md, /No usable cover name was found/);
});

test('renderers work without an explicit translator', function () {
  const md = renderMarkdown(sampleResult());
  assert.match(md, /^# SNI cover analysis/, 'falls back to the default locale');
});

// --- redaction -------------------------------------------------------------

test('redaction blanks operator identity but keeps every verdict', function () {
  const result = sampleResult();
  result.masking.nodeHoster = { asn: 'AS64500', asName: 'EXAMPLE HOSTING LTD', city: 'Example City', countryCode: 'ZZ', description: 'AS64500 EXAMPLE HOSTING LTD', hosting: true };
  result.hoster = { ok: true, asn: 'AS64500', asName: 'EXAMPLE HOSTING LTD', org: 'EXAMPLE HOSTING LTD', city: 'Example City', countryCode: 'ZZ', isp: 'Example ISP', ptr: 'node.example.zz', hosting: true };
  const before = JSON.stringify({ best: result.best, masking: result.masking.verdict, evidence: result.masking.evidence.length });

  const { result: redacted, fields } = redactOperatorDetails(result);
  assert.ok(fields > 0, 'expected fields to be blanked');
  assert.equal(redacted.hoster.asn, REDACTED);
  assert.equal(redacted.hoster.city, REDACTED);
  assert.equal(redacted.masking.nodeHoster.asn, REDACTED);
  assert.equal(redacted.masking.nodeHoster.hosting, true, 'the datacenter flag is not operator identity');
  assert.equal(JSON.stringify({ best: redacted.best, masking: redacted.masking.verdict, evidence: redacted.masking.evidence.length }), before);

  // The source must be untouched: masking evidence aliases the same hoster records, so an
  // in-place redaction would rewrite data the caller still owns.
  assert.equal(result.hoster.asn, 'AS64500', 'redaction must not mutate its input');
  assert.equal(result.masking.nodeHoster.asn, 'AS64500', 'aliased records must survive');

  const md = renderMarkdown(redacted, localizer('ru'));
  assert.ok(md.indexOf('EXAMPLE HOSTING LTD') === -1, 'operator name must be gone');
  assert.ok(md.indexOf('Example City') === -1, 'operator location must be gone');
  assert.match(md, /Рекомендуемый SNI/, 'verdicts survive redaction');
});

test('redaction tolerates odd shapes and keeps the input intact', function () {
  assert.equal(redactOperatorDetails(null).fields, 0);
  assert.equal(redactOperatorDetails('nope').fields, 0);
  const src = { nodes: [{ hoster: { asn: 'AS1' } }] };
  const out = redactOperatorDetails(src);
  assert.ok(out.fields > 0);
  assert.equal(src.nodes[0].hoster.asn, 'AS1', 'the caller keeps its own data');
  assert.equal(out.result.nodes[0].hoster.asn, REDACTED);
});

// --- corpus and certificates ----------------------------------------------

test('candidate corpus is well formed', function () {
  assert.ok(FAST_CANDIDATES.length >= 15);
  assert.ok(REGIONAL.indexOf('www.yandex.ru') !== -1);
  assert.equal(dedupeNames(['a.com', 'A.com ', 'a.com.']).length, 1);
  assert.equal(groupOf('www.microsoft.com'), 'infra');
  assert.equal(groupOf('www.samsung.com'), 'vendor');
  assert.ok(candidatesFor({ fast: true }).length === FAST_CANDIDATES.length);
  assert.ok(candidatesFor({ regional: true }).length > candidatesFor({}).length);
});

test('certificate helpers parse names and SANs', function () {
  assert.equal(cnOf({ CN: 'example.com', O: 'Acme' }), 'example.com');
  assert.equal(normDn('C=US\nO=Acme\nCN=a.com'), normDn('CN=a.com,O=Acme,C=US'));
  const sans = parseSans('DNS:a.com, DNS:*.b.com, IP Address:1.2.3.4');
  assert.equal(sans.length, 3);
  assert.equal(sans[0].type, 'DNS');
  assert.equal(sans[2].type, 'IP');
  assert.ok(trustedRoots().length > 50);
});

test('verifyChain rejects a self-signed certificate for a foreign host', function () {
  const pem = fs.readFileSync(path.join(HERE, 'fixtures', 'selfsigned.pem'));
  const leaf = x509(pem);
  assert.ok(leaf);
  const res = verifyChain(leaf, [], 'www.jetbrains.com');
  assert.equal(res.ok, false);
  assert.equal(res.anchored, false);
  assert.equal(res.selfSigned, true);
  assert.equal(res.hostCovered, false);
});

test('verifyChain accepts a self-signed certificate for its own name, but still not anchored', function () {
  const pem = fs.readFileSync(path.join(HERE, 'fixtures', 'selfsigned.pem'));
  const leaf = x509(pem);
  const res = verifyChain(leaf, [], 'self-test.invalid');
  assert.equal(res.hostCovered, true);
  assert.equal(res.anchored, false, 'a self-signed cert must never count as publicly trusted');
  assert.equal(res.ok, false);
});

// --- interface -------------------------------------------------------------

// A headless harness for the TTY path. Without one this file only ever exercised the
// non-TTY branch, which renders no frames at all — and a crash that fired on the very
// first redraw shipped in a release because of it.
function withFakeTty(opts, body) {
  const columns = (opts && opts.columns) || 120;
  const rows = (opts && opts.rows) || 40;
  const saved = {
    write: process.stdout.write,
    cols: Object.getOwnPropertyDescriptor(process.stdout, 'columns'),
    rows: Object.getOwnPropertyDescriptor(process.stdout, 'rows')
  };
  const chunks = [];
  process.stdout.write = function (c) {
    chunks.push(String(c));
    return true;
  };
  Object.defineProperty(process.stdout, 'columns', { value: columns, configurable: true, writable: true });
  Object.defineProperty(process.stdout, 'rows', { value: rows, configurable: true, writable: true });
  try {
    body(chunks);
  } finally {
    process.stdout.write = saved.write;
    if (saved.cols) Object.defineProperty(process.stdout, 'columns', saved.cols);
    else delete process.stdout.columns;
    if (saved.rows) Object.defineProperty(process.stdout, 'rows', saved.rows);
    else delete process.stdout.rows;
  }
  return chunks;
}

const ESC_RE = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');
const HOME = String.fromCharCode(27) + '[H';
const CLEAR_DOWN = String.fromCharCode(27) + '[J';

/**
 * The last frame written, stripped of escapes and of the trailing padding each line carries.
 * The closing newline is dropped too, so splitting this yields exactly the lines drawn.
 */
function lastFrame(chunks) {
  const text = chunks.join('').split(HOME).pop().split(CLEAR_DOWN)[0];
  const lines = text
    .replace(ESC_RE, '')
    .split('\n')
    .map(function (l) { return l.replace(/ +$/, ''); });
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.join('\n');
}

function driveTui(locale, ttyOpts, steps) {
  return withFakeTty(ttyOpts, function () {
    const { createTui } = tuiModule;
    const tui = createTui({
      targets: [{ address: '203.0.113.7', port: 443 }],
      tty: true,
      t: localizer(locale),
      color: false
    });
    try {
      steps(tui);
    } finally {
      tui.stop();
    }
  });
}

let tuiModule = null;
test('the TUI module loads', async function () {
  tuiModule = await import('../src/tui.js');
  assert.equal(typeof tuiModule.createTui, 'function');
});

test('the TUI draws its first frame without crashing', function () {
  // Regression: a local binding named `t` shadowed the translator in headerLines, so every
  // redraw threw "t is not a function". start() draws a frame immediately, so the first
  // call was already fatal.
  let threw = null;
  const chunks = driveTui('ru', { columns: 100, rows: 30 }, function (tui) {
    try {
      tui.start();
    } catch (e) {
      threw = e;
    }
  });
  assert.equal(threw, null, 'start() must draw a frame: ' + (threw && threw.message));
  const frame = lastFrame(chunks);
  assert.ok(/\p{Script=Cyrillic}/u.test(frame), 'the frame must be localised');
  assert.ok(frame.indexOf('203.0.113.7:443') !== -1, 'the target must appear in the header');
});

test('every TUI event renders a frame', function () {
  const chunks = driveTui('en', { columns: 100, rows: 40 }, function (tui) {
    tui.start();
    tui.onEvent({ type: 'phase', phase: 'discovery', message: msg('progress.discovery', { count: 120 }), total: 120 });
    tui.onEvent({ type: 'discovery', done: 40, total: 120, name: 'a.example', accepted: true });
    tui.onEvent({ type: 'discovery', done: 41, total: 120, name: 'b.example', accepted: false });
    tui.setHoster({ ok: true, asn: 'AS64500', org: 'EXAMPLE HOSTING LTD', city: 'Example City', countryCode: 'ZZ', hosting: true });
    tui.setHoster({ ok: false });
    tui.onEvent({ type: 'phase', phase: 'deep', message: msg('progress.deep', { count: 3 }), total: 3 });
    tui.onEvent({ type: 'deep-start', name: 'a.example', index: 1, total: 3 });
    tui.onEvent({ type: 'deep-done', name: 'a.example', index: 1, total: 3 });
    tui.onEvent({ type: 'unreachable', message: msg('progress.unreachableShort', { message: 'ECONNREFUSED' }) });
    tui.addCandidate({ name: 'a.example' });
    tui.addCandidate({ name: 'b.example', leaf: { cn: 'other.example' }, verified: { ok: false, anchored: false }, forward: { attempted: true, error: 'timeout' }, score: -40 });
    tui.setTarget(null, 0);
    tui.setTarget({ address: '203.0.113.8', port: 443 }, 0);
    tui.finish({
      reachable: true,
      node: { address: '203.0.113.8', port: 443 },
      best: { name: 'b.example', score: 62, grade: 'good', dest: 'b.example:443' },
      masking: { masking: true, method: 'transparent-forward', confidence: 'medium' },
      summary: { notes: [msg('note.weakCover')] },
      candidates: []
    });
  });
  assert.ok(chunks.length > 3, 'the TUI must have written several frames');
  const frame = lastFrame(chunks);
  assert.ok(frame.indexOf('b.example') !== -1, 'the recommendation must be shown');
  assert.ok(frame.indexOf('ECONNREFUSED') !== -1, 'notes must survive to the frame');
});

test('no rendered line exceeds the terminal width', function () {
  // A line wider than the terminal wraps, and every later line of the frame lands one row
  // lower than the cursor arithmetic assumes — the whole display shears.
  for (const width of [60, 80, 120, 160]) {
    const chunks = driveTui('ru', { columns: width, rows: 24 }, function (tui) {
      tui.start();
      tui.onEvent({ type: 'phase', phase: 'deep', message: msg('progress.deep', { count: 3 }), total: 3 });
      for (let i = 0; i < 6; i++) {
        tui.addCandidate({
          name: 'very-long-candidate-name-' + i + '.example',
          leaf: { cn: 'very-long-presented-name-' + i + '.example' },
          verified: { ok: true, anchored: true },
          forward: { attempted: true, comparable: true },
          score: 70 - i,
          stability: { latencyMs: { median: 12 } }
        });
      }
    });
    const lines = lastFrame(chunks).split('\n');
    for (const line of lines) {
      assert.ok(line.length <= width, 'line of ' + line.length + ' cells in a ' + width + '-cell terminal: ' + JSON.stringify(line));
    }
  }
});

test('a short terminal follows the newest candidates while the scan runs', function () {
  const chunks = driveTui('en', { columns: 100, rows: 20 }, function (tui) {
    tui.start();
    tui.onEvent({ type: 'phase', phase: 'deep', message: msg('progress.deep', { count: 14 }), total: 14 });
    for (let i = 0; i < 14; i++) {
      tui.addCandidate({ name: 'n' + i + '.example', leaf: { cn: 'n' + i + '.example' }, verified: { ok: true, anchored: true }, forward: { attempted: true, identityMatch: true }, score: 10 + i, stability: { latencyMs: { median: 12 } } });
    }
  });
  const lines = lastFrame(chunks).split('\n');
  assert.ok(lines.length <= 19, 'the frame must fit the terminal, got ' + lines.length + ' lines');
  assert.ok(lines.join('\n').indexOf('n13.example') !== -1, 'the newest candidate must stay in view');
  assert.ok(lines.join('\n').indexOf('n0.example') === -1, 'the oldest rows must scroll out, not push the frame off');
});

test('navigating the table stops following the tail and shows the selected row', function () {
  const { createTui } = tuiModule;
  const chunks = withFakeTty({ columns: 100, rows: 20 }, function () {
    const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: true, t: localizer('en'), color: false });
    try {
      tui.start();
      for (let i = 0; i < 14; i++) {
        tui.addCandidate({ name: 'n' + i + '.example', leaf: { cn: 'n' + i + '.example' }, verified: { ok: true, anchored: true }, forward: { attempted: true, identityMatch: true }, score: 10 + i, stability: { latencyMs: { median: 12 } } });
      }
      for (let i = 0; i < 6; i++) tui.handleKey('', { name: 'up' });
      return tui;
    } finally {
      tui.stop();
    }
  });
  const frame = lastFrame(chunks);
  // The cursor row is marked with U+25B8; the selected candidate must be on screen and
  // marked, which is the whole point of turning follow off.
  assert.ok(/\u25b8 +\d+ n7\.example/.test(frame), 'the selected row must be marked: ' + JSON.stringify(frame.split('\n').slice(-8)));
  assert.ok(frame.indexOf('n13.example') !== -1, 'the tail is still within one page of the selection');
});

test('createTui degrades to plain progress when not a TTY', async function () {
  const { createTui, createPlainProgress } = await import('../src/tui.js');
  const t = localizer('ru');
  const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: false, t: t });
  const written = [];
  const original = process.stderr.write;
  process.stderr.write = function (s) {
    written.push(String(s));
    return true;
  };
  try {
    tui.start();
    tui.onEvent({ type: 'phase', phase: 'discovery', message: msg('progress.discovery', { count: 20 }), total: 20 });
    tui.onEvent({ type: 'discovery', done: 20, total: 20, name: 'a.com', accepted: true });
    tui.onEvent({ type: 'deep-done', name: 'a.com', index: 1, total: 1 });
    tui.addCandidate({ name: 'a.com', verified: { ok: true, anchored: true }, leaf: { cn: 'a.com' }, score: 90, stability: { latencyMs: { median: 12 } } });
    tui.setHoster({ ok: true, asn: 'AS1', org: 'Acme', hosting: true });
    tui.finish({
      reachable: true,
      node: { address: '203.0.113.7', port: 443 },
      best: { name: 'a.com', score: 90, grade: 'excellent', dest: 'a.com:443' },
      masking: { masking: false, method: 'none', confidence: 'high' },
      summary: { notes: [] },
      candidates: []
    });
    tui.stop();
    const p = createPlainProgress({ write: function (s) { written.push(String(s)); return true; } });
    p({ type: 'discovery', done: 5, total: 20 });
    p({ type: 'phase', message: msg('progress.hoster') });
  } finally {
    process.stderr.write = original;
  }
  const text = written.join('');
  assert.ok(/\p{Script=Cyrillic}/u.test(text), 'non-interactive progress must be localised');
  assert.ok(text.indexOf('5/20') !== -1, 'expected plain progress for the discovery milestone');
});

test('the language prompt lists every locale against a key that actually selects it', async function () {
  const { createTui } = tuiModule;
  // The digit printed against a row must be the digit that selects it: an off-by-one here
  // silently gives the user the language they did not ask for, which is exactly the bug
  // this test was written after.
  assert.deepEqual(LOCALES, ['en', 'ru']);
  for (const c of [
    { press: '1', expect: 'en' },
    { press: '2', expect: 'ru' },
    { press: 'r', expect: 'ru' },
    { press: 'e', expect: 'en' }
  ]) {
    let answer = null;
    withFakeTty({ columns: 100, rows: 30 }, function () {
      const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: true, t: localizer('en'), color: false });
      try {
        tui.start();
        tui.promptLocale('en').then(function (a) { answer = a; });
        tui.handleKey(c.press, { name: c.press });
      } finally {
        tui.stop();
      }
    });
    await new Promise(function (res) { setImmediate(res); });
    assert.equal(answer, c.expect, 'key "' + c.press + '" must select ' + c.expect);
  }
});

test('the prompt numbers the rows it can actually be answered with', function () {
  const { createTui } = tuiModule;
  const chunks = withFakeTty({ columns: 100, rows: 30 }, function () {
    const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: true, t: localizer('en'), color: false });
    try {
      tui.start();
      tui.promptLocale('en');
    } finally {
      tui.stop();
    }
  });
  const frame = lastFrame(chunks);
  assert.ok(/1\s+English/.test(frame), 'the first row must be numbered 1: ' + JSON.stringify(frame.split('\n').slice(-6)));
  assert.ok(/2\s+\S*Русск/.test(frame), 'the second row must be numbered 2');
});

test('the report names the language it was rendered in, and switching it changes the prose', function () {
  const result = sampleResult();
  const en = renderText(result, localizer('en'), { width: 90 });
  const ru = renderText(result, localizer('ru'), { width: 90 });
  assert.notEqual(en, ru);
  assert.ok(/\p{Script=Cyrillic}/u.test(ru));
  assert.ok(!/\p{Script=Cyrillic}/u.test(en), 'the English report must not contain Cyrillic');
});

test('utility helpers behave', function () {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 2, 3]), 2.5);
  assert.equal(median([]), null);
  assert.equal(isBenchmarkIp('198.18.15.189'), true);
  assert.equal(isBenchmarkIp('8.8.8.8'), false);
  assert.equal(isIp('1.2.3.4'), true);
  assert.equal(isIp('999.2.3.4'), false);
  assert.equal(isIp('2001:db8::1'), true);
  assert.equal(clip('abcdef', 4).length, 4);
});

test('the published repository contains no real operator identity', function () {
  // A regression guard: fixture data must not name a real hosting provider or city.
  const files = ['../src/selftest.js', '../src/i18n/en.js', '../src/i18n/ru.js', './unit.test.js', '../README.md'];
  // Assembled from fragments so this guard does not trip over its own source, which would
  // otherwise have to contain the very strings it forbids.
  const banned = [new RegExp('ih' + 'or', 'i'), new RegExp('hel' + 'sinki', 'i'), new RegExp('207' + '569')];
  for (const rel of files) {
    const p = path.join(HERE, rel);
    if (!fs.existsSync(p)) continue;
    const text = fs.readFileSync(p, 'utf8');
    for (const re of banned) {
      assert.ok(!re.test(text), rel + ' must not mention ' + re);
    }
  }
  assert.ok(VERSION.length > 0);
});

// --- regression tests for the design review ---------------------------------
//
// Each one is written against a defect that shipped: a header that labelled the wrong
// column, two numbers that fused into one, a cell that printed "[object Object]", a verdict
// that contradicted the evidence under it, and progress that never reached its total.

test('the table header sits over the columns it labels', function () {
  const t = localizer('ru');
  const chunks = driveTui('ru', { columns: 100, rows: 30 }, function (tui) {
    tui.start();
    tui.onEvent({ type: 'phase', phase: 'deep', message: msg('progress.deep', { count: 2 }), total: 2 });
    tui.addCandidate({
      name: 'a.example',
      leaf: { cn: 'other.example' },
      verified: { ok: true, anchored: true },
      forward: { attempted: true, identityMatch: true },
      score: 92,
      grade: 'excellent',
      stability: { latencyMs: { median: 124.4 } }
    });
  });
  const lines = lastFrame(chunks).split('\n');
  const header = lines.find(function (l) { return l.indexOf(t('tui.candidate')) !== -1; });
  const row = lines.find(function (l) { return l.indexOf('a.example') !== -1; });
  assert.ok(header && row, 'the table must have a header and a row');
  // The header used to indent by pad + rankW and then leave the rank cell empty, putting
  // every heading four cells to the right of its column. Both lines now spend exactly the
  // same six cells before the first column, so each heading must sit at offset zero.
  assert.equal(header.indexOf(t('tui.candidate')) - row.indexOf('a.example'), 0,
    'the name heading is not over the name column');
  assert.equal(header.indexOf(t('tui.presentedAs')) - row.indexOf('other.example'), 0,
    'the second column heading is not over the second column');
  assert.equal(header.indexOf(t('tui.forward')) - row.indexOf(t('forward.identical')), 0,
    'the forward heading is not over the forward column');
});

test('the score and the latency never fuse into one number', function () {
  const chunks = driveTui('ru', { columns: 100, rows: 30 }, function (tui) {
    tui.start();
    tui.onEvent({ type: 'phase', phase: 'deep', message: msg('progress.deep', { count: 1 }), total: 1 });
    tui.addCandidate({
      name: 'a.example',
      leaf: { cn: 'a.example' },
      verified: { ok: true, anchored: true },
      forward: { attempted: true, identityMatch: true },
      score: 92,
      grade: 'excellent',
      stability: { latencyMs: { median: 138 } }
    });
  });
  const row = lastFrame(chunks).split('\n').find(function (l) { return l.indexOf('a.example') !== -1; });
  // '92' and '138' in adjacent right-aligned columns rendered as '92138' when the score
  // column was sized from its heading rather than from the values it holds.
  assert.ok(/92\s+138/.test(row), 'score and latency must stay apart: ' + JSON.stringify(row));
});

test('an unmeasured node is scored as unmeasured, not as perfect', function () {
  // Zero distinct fingerprints is not determinism and an attempted-but-unmeasured forward is
  // not an absent one; both were stated as fact about a node that never answered.
  const score = scoreCandidate({
    name: 'a.example',
    verified: { ok: false, anchored: false },
    stability: { attempts: 0, successRate: 0, deterministic: true },
    forward: { attempted: true }
  }, {});
  const keys = score.components.map(function (c) { return c.reason.key; });
  assert.ok(keys.indexOf('score.forwardNotComparable') !== -1, 'got ' + JSON.stringify(keys));
  assert.ok(keys.indexOf('score.forwardNone') === -1, 'an attempted forward is not an absent one');
  assert.ok(keys.indexOf('score.deterministic') === -1, 'nothing measured establishes no determinism');
  assert.ok(keys.indexOf('score.stableAll') === -1, 'a zero success rate is not a full one');
});

test('redirect hops are counted, not printed as objects', function () {
  const result = sampleResult();
  result.candidates[0].forward.via.hops = [{ status: 301 }, { status: 302 }];
  result.candidates[0].forward.direct.hops = [{}];
  const text = renderText(result, localizer('ru'), { width: 100 });
  assert.ok(text.indexOf('[object Object]') === -1, 'hops must render as a count');
  assert.ok(/Редиректов\s+2\s+1/.test(text), 'expected 2 and 1 redirects');
});

test('the language prompt offers every locale, in the order the keys select', function () {
  let prompt = null;
  const chunks = withFakeTty({ columns: 90, rows: 24 }, function () {
    const { createTui } = tuiModule;
    const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: true, t: localizer('en'), color: false });
    prompt = tui.promptLocale('en');
    tui.handleKey('2', { name: '2' });
    tui.stop();
  });
  const frame = lastFrame(chunks);
  for (const loc of LOCALES) {
    assert.ok(frame.indexOf(LOCALE_NAMES[loc]) !== -1, 'the prompt must offer ' + loc);
  }
  return prompt.then(function (chosen) {
    assert.equal(chosen, LOCALES[1], 'the digit 2 must select the second row printed');
  });
});

test('colour is a per-instance switch, not a process-wide one', function () {
  const { createTui } = tuiModule;
  // NO_COLOR is honoured ahead of the option, so it has to be out of the way for this test;
  // the CI running it is exactly the kind of environment that sets it.
  const savedNoColor = process.env.NO_COLOR;
  delete process.env.NO_COLOR;
  const frameOf = function (color) {
    return withFakeTty({ columns: 90, rows: 24 }, function () {
      const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: true, t: localizer('en'), color: color });
      tui.start();
      tui.stop();
    }).join('');
  };
  // Colour escapes only: every frame carries cursor movement even without colour.
  const colour = new RegExp(String.fromCharCode(27) + '\\[(3|4|9|10)[0-9]m');
  try {
    assert.ok(!colour.test(frameOf(false)), 'a colourless instance must emit no colour');
    // The first instance used to blank the shared palette object, so every later one stayed
    // colourless for the life of the process.
    assert.ok(colour.test(frameOf(true)), 'a later colour instance must still emit colour');
  } finally {
    if (savedNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = savedNoColor;
  }
});

