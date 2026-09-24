// Self test: run the whole pipeline against a locally started fake "masking hoster".
//
// The fixture stands up three TLS listeners on loopback, each reproducing one real-world
// masking pattern, and points the analyser at them. No external network access is needed
// for the core assertions, so this doubles as a regression test.
//
//   genuine       presents a publicly trusted certificate for the name it owns
//   forged        mints its own certificate for a domain it does not own
//   catchall      presents one certificate for every name, including undeclared ones
//
// The hoster records below are deliberately fictional. A self test that hard-codes a real
// provider's name, ASN and city leaks that infrastructure into every published copy of the
// repository and makes the test fail the moment the fixture moves, so these values stand
// for "some hosting provider" and nothing else.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { analyzeNode } from './analyze.js';
import { evaluateMasking } from './masking.js';
import { trustedRoots, x509 } from './cert.js';
import { localizer, DEFAULT_LOCALE, CATALOGUES } from './i18n/index.js';
import { redactOperatorDetails, REDACTED } from './redact.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, '..', 'test', 'fixtures');

// Fictional operators for the fixtures: one node-side, one reference-side.
export const FIXTURE_NODE_HOSTER = {
  ok: true,
  asn: 'AS64500',
  asName: 'EXAMPLE HOSTING LTD',
  org: 'EXAMPLE HOSTING LTD',
  city: 'Example City',
  countryCode: 'ZZ',
  hosting: true
};
export const FIXTURE_REFERENCE_HOSTER = {
  ok: true,
  asn: 'AS64501',
  asName: 'EXAMPLE CDN INC',
  org: 'EXAMPLE CDN INC',
  countryCode: 'ZZ',
  hosting: true
};

function loadSelfSigned() {
  const certPath = path.join(FIXTURES, 'selfsigned.pem');
  if (!fs.existsSync(certPath)) return null;
  return { cert: fs.readFileSync(certPath), key: fs.readFileSync(path.join(FIXTURES, 'key.pem')) };
}

function startListener(pair, behaviour) {
  return new Promise(function (resolve) {
    const server = https.createServer({ cert: pair.cert, key: pair.key }, function (req, res) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('sni-recon fixture [' + behaviour + '] ' + req.headers.host + '\n');
    });
    server.on('tlsClientError', function () {
      /* probes that we reject are expected */
    });
    server.listen(0, '127.0.0.1', function () {
      resolve({ server: server, port: server.address().port });
    });
  });
}

function check(results, name, condition, detail) {
  results.push({ name: name, pass: !!condition, detail: detail || '' });
}

export async function runSelftest(opts, tIn) {
  const t = typeof tIn === 'function' ? tIn : localizer(DEFAULT_LOCALE);
  const results = [];
  const pair = loadSelfSigned();
  if (!pair) {
    process.stderr.write(t('selftest.fixturesMissing') + '\n');
    return 2;
  }

  const leaf = x509(pair.cert);
  check(results, 'selftest.fixtureLoads', !!leaf, leaf ? 'CN=' + leaf.subject : 'unparsable');
  check(
    results,
    'selftest.fixtureNotTrusted',
    !trustedRoots().some(function (r) {
      return r.fingerprint256 === leaf.fingerprint256;
    }),
    t('selftest.detail.forgedStandIn')
  );

  const listeners = [];
  try {
    // 1. A node that mints certificates for a foreign domain.
    const forged = await startListener(pair, 'forged');
    listeners.push(forged);
    const forgedResult = await analyzeNode(
      { address: '127.0.0.1', port: forged.port },
      {
        serverNames: ['www.jetbrains.com', 'www.example.org'],
        repeat: 2,
        gap: 30,
        concurrency: 2,
        timeout: 4000,
        reference: false,
        hoster: false,
        verbose: !!(opts && opts.verbose)
      }
    );
    check(results, 'selftest.forgedAccepted', forgedResult.whitelist.accepted === 2, 'accepted=' + forgedResult.whitelist.accepted);
    check(
      results,
      'selftest.forgedUntrusted',
      forgedResult.candidates.every(function (c) {
        return c.verified && !c.verified.anchored;
      }),
      t('selftest.detail.noAnchor')
    );
    check(
      results,
      'selftest.forgedLookalike',
      forgedResult.candidates.every(function (c) {
        return !c.verified.ok;
      }),
      t('selftest.detail.chainRejects')
    );
    check(
      results,
      'selftest.forgedCatchall',
      forgedResult.whitelist.randomNameAccepted === true,
      t('selftest.detail.answersEverySni')
    );
    const masking = evaluateMasking({
      nodeHoster: FIXTURE_NODE_HOSTER,
      referenceHoster: FIXTURE_REFERENCE_HOSTER,
      controls: forgedResult.controls,
      candidates: forgedResult.candidates,
      genericIdentity: forgedResult.whitelist.genericIdentity
    });
    check(results, 'selftest.maskingForged', masking.masking === true && masking.method === 'forged-certificate', 'method=' + masking.method);
    check(results, 'selftest.maskingHigh', masking.confidence === 'high', 'confidence=' + masking.confidence);
    check(results, 'selftest.maskingOperator', masking.sameOperator === false, t('selftest.detail.nodeVsReference'));
    check(
      results,
      'selftest.maskingEvidenceLocalised',
      typeof masking.evidence[0].detail === 'object' && typeof masking.evidence[0].detail.key === 'string',
      t('selftest.detail.structuredEvidence')
    );

    // 2. A node that presents one catch-all certificate but mints it for itself.
    const catchall = await startListener(pair, 'catchall');
    listeners.push(catchall);
    const catchallResult = await analyzeNode(
      { address: '127.0.0.1', port: catchall.port },
      { serverNames: ['www.microsoft.com'], repeat: 2, gap: 30, timeout: 4000, reference: false, hoster: false }
    );
    check(
      results,
      'selftest.catchallGeneric',
      catchallResult.whitelist.genericIdentity === true,
      'genericIdentity=' + catchallResult.whitelist.genericIdentity
    );

    // 3. Report rendering must survive every shape of result, in every locale.
    forgedResult.masking = masking;
    const { renderMarkdown, renderText, render } = await import('./report.js');
    const md = renderMarkdown(forgedResult, t);
    check(results, 'selftest.mdRenders', md.indexOf('# ') === 0, md.length + ' bytes');
    check(results, 'selftest.mdMasking', md.indexOf(t('masking.heading')) !== -1, '');
    // A name that scored poorly must NOT be presented as a recommendation. Handing the
    // reader a ready-to-paste configuration for it would be actively misleading.
    check(results, 'selftest.mdNoConfigForWeak', md.indexOf('"serverNames"') === -1, t('selftest.detail.noConfigForWeak'));

    // ...while a usable name must still get one.
    const goodCopy = JSON.parse(JSON.stringify(forgedResult));
    goodCopy.candidates = goodCopy.candidates.map(function (c) {
      return Object.assign({}, c, { grade: 'excellent', score: 88 });
    });
    goodCopy.best = { name: goodCopy.candidates[0].name, score: 88, grade: 'excellent', dest: goodCopy.candidates[0].name + ':443' };
    const goodMd = renderMarkdown(goodCopy, t);
    check(results, 'selftest.mdConfig', goodMd.indexOf('"serverNames"') !== -1, '');
    check(results, 'selftest.mdConclusionFirst', md.indexOf(t('conclusion.heading')) < md.indexOf(t('method.heading')), t('selftest.detail.answerFirst'));
    check(results, 'selftest.txtRenders', renderText(forgedResult, t).indexOf('sni-recon') !== -1, '');
    check(
      results,
      'selftest.jsonParses',
      (function () {
        try {
          JSON.parse(render(forgedResult, 'json'));
          return true;
        } catch (e) {
          return false;
        }
      })(),
      ''
    );

    // 4. Every shipped locale must cover every key, and must render without leaking keys.
    const locales = Object.keys(CATALOGUES);
    const enKeys = Object.keys(CATALOGUES[DEFAULT_LOCALE]);
    let missing = [];
    for (const loc of locales) {
      for (const k of enKeys) {
        if (!(k in CATALOGUES[loc])) missing.push(loc + ':' + k);
      }
    }
    check(results, 'selftest.localeParity', missing.length === 0, missing.slice(0, 5).join(', ') || locales.join(', '));

    // A missing translation must never surface as a raw key in a report.
    let leaked = [];
    for (const loc of locales) {
      const lt = localizer(loc);
      const text = renderMarkdown(forgedResult, lt) + renderText(forgedResult, lt);
      for (const k of enKeys) {
        if (text.indexOf(k) !== -1) leaked.push(loc + ':' + k);
      }
    }
    check(results, 'selftest.localeNoKeyLeak', leaked.length === 0, leaked.slice(0, 5).join(', ') || locales.join(', '));

    // The Russian report must actually be Russian, not English with a Russian header.
    const ru = renderMarkdown(forgedResult, localizer('ru'));
    check(results, 'selftest.ruReportIsRussian', ru.indexOf(t('masking.heading')) === -1 && /\p{Script=Cyrillic}/u.test(ru), 'Cyrillic present');

    // 5. Redaction must remove operator identity without changing any verdict.
    const beforeVerdict = forgedResult.masking.verdict;
    const beforeScore = forgedResult.best ? forgedResult.best.score : null;
    const redacted = redactOperatorDetails(forgedResult);
    const redactedFields = redacted.fields;
    // The input must survive: masking evidence aliases the same hoster records, so an
    // in-place redaction would silently rewrite the caller's fixtures.
    const sourceIntact =
      FIXTURE_NODE_HOSTER.asName !== REDACTED &&
      FIXTURE_NODE_HOSTER.city !== REDACTED &&
      forgedResult.masking.nodeHoster.asn === FIXTURE_NODE_HOSTER.asn;
    const asnGone = redacted.result.masking.nodeHoster.asn === REDACTED;
    const verdictKept =
      redacted.result.masking.verdict === beforeVerdict && (redacted.result.best ? redacted.result.best.score : null) === beforeScore;
    const ruRedacted = renderMarkdown(redacted.result, localizer('ru'));
    check(results, 'selftest.redaction', redactedFields > 0 && asnGone, redactedFields + ' ' + t('selftest.detail.fieldsBlanked'));
    check(results, 'selftest.redactionKeepsVerdicts', verdictKept, t('selftest.detail.verdictsIntact'));
    check(results, 'selftest.redactionNonDestructive', sourceIntact, t('selftest.detail.sourceIntact'));
    check(
      results,
      'selftest.redactionNoLeak',
      ruRedacted.indexOf(FIXTURE_NODE_HOSTER.asName) === -1 && ruRedacted.indexOf(FIXTURE_NODE_HOSTER.city) === -1,
      t('selftest.detail.operatorGone')
    );

    // 6. Scoring must rank a genuine identity above a forged one.
    const genuine = forgedResult.candidates.map(function (c) {
      return Object.assign({}, c, { verified: { ok: true, anchored: true }, forward: { identityMatch: true } });
    });
    const { scoreCandidate } = await import('./analyze.js');
    const g = scoreCandidate(genuine[0], { referenceFingerprint: genuine[0].fingerprint256 });
    const f = scoreCandidate(forgedResult.candidates[0], {});
    check(results, 'selftest.scoring', g.score > f.score, 'genuine=' + g.score + ' forged=' + f.score);
  } finally {
    for (const l of listeners) {
      await new Promise(function (res) {
        l.server.close(res);
      });
    }
  }

  const failed = results.filter(function (r) {
    return !r.pass;
  });
  const out = [];
  out.push('');
  out.push('sni-recon ' + t('selftest.heading') + '  [' + t.locale + ']');
  out.push('='.repeat(64));
  for (const r of results) {
    out.push((r.pass ? '  ' + t('selftest.pass') + '  ' : '  ' + t('selftest.fail') + '  ') + t(r.name) + (r.detail ? '  \u2014 ' + r.detail : ''));
  }
  out.push('-'.repeat(64));
  out.push('  ' + t('selftest.summary', { passed: results.length - failed.length, total: results.length }));
  out.push('');
  process.stdout.write(out.join('\n'));
  return failed.length ? 1 : 0;
}
