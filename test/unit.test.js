// Node test-runner suite over the pure parts of the tool: scoring, hoster comparison,
// certificate verification, and report rendering.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scoreCandidate, gradeOf } from '../src/analyze.js';
import { sameOperator, describeHoster } from '../src/hoster.js';
import { evaluateMasking, METHOD } from '../src/masking.js';
import { renderMarkdown, renderText, render, defaultOutPath } from '../src/report.js';
import { dedupeNames, candidatesFor, FAST_CANDIDATES, REGIONAL, groupOf } from '../src/candidates.js';
import { parseSans, cnOf, normDn, trustedRoots, verifyChain, x509 } from '../src/cert.js';
import { median, isBenchmarkIp, isIp, clip } from '../src/util.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

test('gradeOf maps scores to grades', function () {
  assert.equal(gradeOf(90), 'excellent');
  assert.equal(gradeOf(80), 'excellent');
  assert.equal(gradeOf(65), 'good');
  assert.equal(gradeOf(45), 'fair');
  assert.equal(gradeOf(0), 'poor');
  assert.equal(gradeOf(-20), 'poor');
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

test('sameOperator matches on ASN and on organisation name', function () {
  assert.equal(sameOperator({ ok: true, asn: 'AS1' }, { ok: true, asn: 'AS1' }), true);
  assert.equal(sameOperator({ ok: true, asn: 'AS1' }, { ok: true, asn: 'AS2' }), false);
  assert.equal(sameOperator({ ok: true, asn: 'AS1', org: 'Acme Hosting Ltd' }, { ok: true, org: 'ACME HOSTING' }), true);
  assert.equal(sameOperator({ ok: false }, { ok: true, asn: 'AS1' }), null);
});

test('describeHoster renders a readable summary', function () {
  const s = describeHoster({ ok: true, asn: 'AS207569', asName: 'IHOR HOSTING LTD', city: 'Helsinki', countryCode: 'FI' });
  assert.match(s, /AS207569/);
  assert.match(s, /Helsinki/);
  assert.equal(describeHoster(null), 'unknown');
});

test('evaluateMasking detects a forged certificate at high confidence', function () {
  const m = evaluateMasking({
    nodeHoster: { ok: true, asn: 'AS207569', org: 'IHOR HOSTING LTD', hosting: true, countryCode: 'FI' },
    referenceHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true, countryCode: 'US' },
    controls: { randomName: { ok: true, name: 'x.invalid' } },
    candidates: [{ name: 'www.jetbrains.com', verified: { ok: false, anchored: false }, leaf: { issuerCn: 'WR2' } }],
    genericIdentity: false
  });
  assert.equal(m.masking, true);
  assert.equal(m.method, METHOD.FORGED);
  assert.equal(m.confidence, 'high');
  assert.ok(m.evidence.length >= 2);
});

test('evaluateMasking clears a node that is the genuine service', function () {
  const m = evaluateMasking({
    nodeHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true },
    referenceHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true },
    controls: { randomName: { ok: false }, strictName: { ok: false } },
    candidates: [
      {
        name: 'www.amazon.com',
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

test('evaluateMasking does not flag a node that IS the real service', function () {
  // Same operator, honestly issued certificate, byte-identical content: the node is the
  // service's own front-end. Any masking verdict here would be a false positive.
  const m = evaluateMasking({
    nodeHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true },
    referenceHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true },
    controls: { randomName: { ok: false }, strictName: { ok: false } },
    candidates: [
      {
        name: 'www.example.com',
        verified: { ok: true, anchored: true },
        fingerprint256: 'AA',
        reference: { ok: true, leafFingerprint256: 'AA', keyExchange: { name: 'X25519' } },
        via: { keyExchange: { name: 'X25519' } },
        forward: { attempted: true, identityMatch: true, comparable: true }
      }
    ],
    genericIdentity: false
  });
  assert.equal(m.masking, false, 'a genuine front-end must not be reported as masked');
  assert.equal(m.verdict, 'genuine-front');
});

test('evaluateMasking still flags a forged node when candidates were never deep-analysed', function () {
  const m = evaluateMasking({
    nodeHoster: { ok: true, asn: 'AS207569', org: 'IHOR HOSTING LTD', hosting: true },
    referenceHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true },
    controls: { randomName: { ok: true, name: 'x.invalid' } },
    // No `stability` field: this is what --no-deep produces.
    candidates: [{ name: 'www.jetbrains.com', verified: { ok: false, anchored: false }, leaf: { issuerCn: 'WR2' } }],
    genericIdentity: false
  });
  assert.equal(m.masking, true);
  assert.equal(m.method, METHOD.FORGED);
});

test('renderMarkdown emits a usable report skeleton', function () {
  const result = {
    node: { address: '203.0.113.7', port: 443 },
    startedAt: '2026-01-01T00:00:00Z',
    finishedAt: '2026-01-01T00:01:00Z',
    reachable: true,
    controls: { noSni: { ok: false, error: 'ECONNRESET' }, strictName: { ok: false, name: 'invalid2.invalid' }, randomName: { ok: true, name: 'x.invalid' } },
    whitelist: { tested: 50, accepted: 1, acceptedNames: ['www.example.com'], rejectedSample: [{ name: 'www.other.com' }], distinctIdentities: 1, genericIdentity: false, randomNameAccepted: true, realitlscannerCompatible: false },
    candidates: [
      {
        name: 'www.example.com',
        group: 'infra',
        score: 88,
        grade: 'excellent',
        leaf: { cn: 'www.example.com', issuerCn: 'DigiCert', validFrom: '2025-01-01', validTo: '2027-01-01', fingerprint256: 'AB:CD:EF:01:23:45:67:89:AA:BB:CC:DD:EE:FF:00:11' },
        verified: { ok: true, anchored: true },
        validityDaysLeft: 300,
        stability: { ok: 5, attempts: 5, deterministic: true, latencyMs: { min: 10, median: 12, max: 20 } },
        forward: { attempted: true, identityMatch: true, comparable: true, checks: { status: 'match', bytes: 'match (100)', bodyHash: 'identical' }, via: { status: 200, bytes: 100, ttfbMs: 30 }, direct: { status: 200, bytes: 100, ttfbMs: 80 }, differences: [] },
        scoreComponents: [{ points: 35, reason: 'genuine' }]
      }
    ],
    best: { name: 'www.example.com', score: 88, grade: 'excellent', dest: 'www.example.com:443' },
    masking: { masking: false, method: 'none', confidence: 'high', verdict: 'genuine-front', headline: 'No masking detected.', weight: -2, evidence: [{ signal: 'operator-match', weight: -2, detail: 'same organisation' }], sameOperator: true, nodeHoster: { description: 'AS16509 AMAZON-02' }, referenceHoster: { description: 'AS16509 AMAZON-02' } },
    summary: { bestName: 'www.example.com', notes: ['all good'] }
  };
  const md = renderMarkdown(result);
  assert.match(md, /^# SNI cover analysis/);
  assert.match(md, /Recommended SNI/);
  assert.match(md, /"serverNames": \["www\.example\.com"\]/);
  assert.match(md, /Hoster-level domain masking/);
  assert.match(md, /Candidate ranking/);
  assert.ok(md.indexOf(String.fromCharCode(96, 96, 96, 34)) === -1, 'no stray escaped fence');
  const txt = renderText(result);
  assert.match(txt, /RECOMMENDED/);
  assert.match(JSON.parse(render(result, 'json')).node.address, /203\.0\.113\.7/);
  assert.equal(defaultOutPath(result, 'json'), 'sni-recon-203.0.113.7.json');
});

test('renderMarkdown handles an unreachable node', function () {
  const md = renderMarkdown({
    node: { address: '203.0.113.9', port: 443 },
    startedAt: '2026-01-01T00:00:00Z',
    reachable: false,
    summary: { message: 'no handshake', verdict: 'unreachable' }
  });
  assert.match(md, /No TLS handshake completed/);
});

test('renderMarkdown handles a node that accepts nothing', function () {
  const md = renderMarkdown({
    node: { address: '203.0.113.9', port: 443 },
    startedAt: '2026-01-01T00:00:00Z',
    reachable: true,
    controls: {},
    whitelist: { tested: 10, accepted: 0, rejectedSample: [] },
    candidates: [],
    best: null,
    summary: { verdict: 'no-candidate-accepted', message: 'nothing accepted' }
  });
  assert.match(md, /No usable cover name was found/);
});

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

test('createTui degrades to plain progress when not a TTY', async function () {
  const { createTui, createPlainProgress } = await import('../src/tui.js');
  const tui = createTui({ targets: [{ address: '203.0.113.7', port: 443 }], tty: false });
  const written = [];
  const original = process.stderr.write;
  process.stderr.write = function (s) {
    written.push(String(s));
    return true;
  };
  try {
    tui.start();
    tui.onEvent({ type: 'phase', phase: 'discovery', message: 'probing 20 names', total: 20 });
    tui.onEvent({ type: 'discovery', done: 20, total: 20, name: 'a.com', accepted: true });
    tui.onEvent({ type: 'deep-done', name: 'a.com', index: 1, total: 1 });
    tui.addCandidate({ name: 'a.com', verified: { ok: true, anchored: true }, leaf: { cn: 'a.com' }, score: 90, stability: { latencyMs: { median: 12 } } });
    tui.setHoster({ ok: true, asn: 'AS1', org: 'Acme', hosting: true });
    tui.finish({ reachable: true, node: { address: '203.0.113.7', port: 443 }, best: { name: 'a.com', score: 90, grade: 'excellent', dest: 'a.com:443' }, masking: { masking: false, method: 'none', confidence: 'high' }, summary: { notes: [] }, candidates: [] });
    tui.stop();
    const p = createPlainProgress({ write: function (s) { written.push(String(s)); return true; } });
    p({ type: 'discovery', done: 5, total: 20 });
    p({ type: 'phase', message: 'done' });
  } finally {
    process.stderr.write = original;
  }
  const text = written.join('');
  assert.match(text, /non-interactive/);
  assert.ok(text.indexOf('discovery 5/20') !== -1, 'expected plain progress for the discovery milestone');
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
