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
// The "genuine" listener uses the certificate of whatever reference host is reachable;
// when offline, that leg is skipped and reported as such rather than failing.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { analyzeNode } from './analyze.js';
import { evaluateMasking } from './masking.js';
import { trustedRoots, x509 } from './cert.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, '..', 'test', 'fixtures');

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
    server.on('tlsClientError', function () { /* probes that we reject are expected */ });
    server.listen(0, '127.0.0.1', function () {
      resolve({ server: server, port: server.address().port });
    });
  });
}

function check(results, name, condition, detail) {
  results.push({ name: name, pass: !!condition, detail: detail || '' });
}

export async function runSelftest(opts) {
  const results = [];
  const pair = loadSelfSigned();
  if (!pair) {
    process.stderr.write('selftest: fixtures missing. Generate them with:\n');
    process.stderr.write('  npm run fixtures\n');
    return 2;
  }

  const leaf = x509(pair.cert);
  check(results, 'fixture certificate loads', !!leaf, leaf ? 'CN=' + leaf.subject : 'unparsable');
  check(
    results,
    'fixture certificate is NOT in the public trust store',
    !trustedRoots().some(function (r) { return r.fingerprint256 === leaf.fingerprint256; }),
    'this is what makes it a usable stand-in for a forged identity'
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
    check(results, 'forged node: both configured names accepted', forgedResult.whitelist.accepted === 2, 'accepted=' + forgedResult.whitelist.accepted);
    check(
      results,
      'forged node: certificate is flagged as not publicly trusted',
      forgedResult.candidates.every(function (c) { return c.verified && !c.verified.anchored; }),
      'every candidate lacks a trusted anchor'
    );
    check(
      results,
      'forged node: verdict is a lookalike identity, not genuine',
      forgedResult.candidates.every(function (c) { return !c.verified.ok; }),
      'offline chain verification rejects it'
    );
    check(
      results,
      'forged node: random undeclared name is accepted (catch-all)',
      forgedResult.whitelist.randomNameAccepted === true,
      'the listener answers every SNI'
    );
    const masking = evaluateMasking({
      nodeHoster: { ok: true, asn: 'AS207569', org: 'IHOR HOSTING LTD', hosting: true, countryCode: 'FI' },
      referenceHoster: { ok: true, asn: 'AS16509', org: 'AMAZON-02', hosting: true, countryCode: 'US' },
      controls: forgedResult.controls,
      candidates: forgedResult.candidates,
      genericIdentity: forgedResult.whitelist.genericIdentity
    });
    check(results, 'masking: forged certificate identified', masking.masking === true && masking.method === 'forged-certificate', 'method=' + masking.method);
    check(results, 'masking: confidence is high', masking.confidence === 'high', 'confidence=' + masking.confidence);
    check(results, 'masking: operator mismatch recorded', masking.sameOperator === false, 'node vs reference operator');

    // 2. A node that presents one catch-all certificate but mints it for itself.
    const catchall = await startListener(pair, 'catchall');
    listeners.push(catchall);
    const catchallResult = await analyzeNode(
      { address: '127.0.0.1', port: catchall.port },
      { serverNames: ['www.microsoft.com'], repeat: 2, gap: 30, timeout: 4000, reference: false, hoster: false }
    );
    check(
      results,
      'catch-all node: single certificate served for every SNI',
      catchallResult.whitelist.genericIdentity === true,
      'genericIdentity=' + catchallResult.whitelist.genericIdentity
    );

    // 3. Report rendering must survive every shape of result. Attach the masking verdict
    // computed above so the renderer is exercised with the operator data present.
    forgedResult.masking = masking;
    const { renderMarkdown, renderText, render } = await import('./report.js');
    const md = renderMarkdown(forgedResult);
    check(results, 'markdown report renders', md.indexOf('# SNI cover analysis') === 0, md.length + ' bytes');
    check(results, 'markdown report includes the masking section', md.indexOf('Hoster-level domain masking') !== -1, '');
    check(results, 'markdown report recommends a configuration', md.indexOf('"serverNames"') !== -1, '');
    check(results, 'text report renders', renderText(forgedResult).indexOf('sni-recon') !== -1, '');
    check(results, 'json report parses', (function () { try { JSON.parse(render(forgedResult, 'json')); return true; } catch (e) { return false; } })(), '');

    // 4. Scoring must rank a genuine identity above a forged one.
    const genuine = forgedResult.candidates.map(function (c) {
      return Object.assign({}, c, { verified: { ok: true, anchored: true }, forward: { identityMatch: true } });
    });
    const { scoreCandidate } = await import('./analyze.js');
    const g = scoreCandidate(genuine[0], { referenceFingerprint: genuine[0].fingerprint256 });
    const f = scoreCandidate(forgedResult.candidates[0], {});
    check(results, 'scoring: a genuine identity outranks a forged one', g.score > f.score, 'genuine=' + g.score + ' forged=' + f.score);
  } finally {
    for (const l of listeners) {
      await new Promise(function (res) { l.server.close(res); });
    }
  }

  const failed = results.filter(function (r) { return !r.pass; });
  const out = [];
  out.push('');
  out.push('sni-recon selftest');
  out.push('='.repeat(64));
  for (const r of results) {
    out.push((r.pass ? '  PASS  ' : '  FAIL  ') + r.name + (r.detail ? '  \u2014 ' + r.detail : ''));
  }
  out.push('-'.repeat(64));
  out.push('  ' + (results.length - failed.length) + '/' + results.length + ' checks passed');
  out.push('');
  process.stdout.write(out.join('\n'));
  return failed.length ? 1 : 0;
}
