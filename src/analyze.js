// Analysis engine.
//
// Three questions, asked in increasing order of strength:
//
//   1. WHICH names does the node accept?          -> handshake probe matrix
//   2. Is that identity REAL or a lookalike?      -> offline chain verification
//   3. Does it actually CARRY the site's traffic? -> IP-pinned request vs. the real site
//
// A node can pass (1) while failing (2), and that combination is the single most useful
// finding this tool produces: a node that emits a self-minted certificate for a popular
// hostname will look fine to a naive handshake test and wrong to anyone who inspects.
import { probeTls, probeTlsStable, probeNoSni } from './probe.js';
import { resolveHost, pickAddress } from './dns.js';
import { requestPinned, requestFollow } from './http.js';
import { pool, median, round, errText, log } from './util.js';
import { candidatesFor, dedupeNames, groupOf } from './candidates.js';
import { lookupHoster } from './hoster.js';
import { evaluateMasking } from './masking.js';
import { msg } from './messages.js';

// Names that no TLS stack can honestly own. Used as control probes.
const STRICT_NAME = 'invalid2.invalid';

function emit(opts, evt) {
  if (!opts || !opts.onEvent) return;
  try {
    opts.onEvent(evt);
  } catch (e) {
    /* a broken listener must never abort a scan */
  }
}

export function normalizeOptions(options) {
  const o = options || {};
  return {
    port: o.port || 443,
    timeout: o.timeout == null ? 8000 : o.timeout,
    concurrency: o.concurrency == null ? 10 : o.concurrency,
    repeat: o.repeat == null ? 5 : o.repeat,
    gap: o.gap == null ? 120 : o.gap,
    maxDeep: o.maxDeep == null ? 10 : o.maxDeep,
    reference: o.reference !== false,
    followRedirects: o.followRedirects !== false,
    deep: o.deep !== false,
    assets: o.assets || [],
    verbose: !!o.verbose,
    serverNames: o.serverNames || [],
    candidates: o.candidates || null,
    fast: !!o.fast,
    regional: !!o.regional,
    cache: o.cache !== false,
    hoster: o.hoster !== false,
    onEvent: typeof o.onEvent === 'function' ? o.onEvent : null
  };
}

function daysLeft(validTo) {
  const t = Date.parse(validTo);
  if (!Number.isFinite(t)) return null;
  return Math.floor((t - Date.now()) / 86400000);
}

/** Stage 1: which candidate names complete a handshake? */
async function probeWhitelist(host, port, names, opts) {
  let done = 0;
  const results = await pool(names, opts.concurrency, async function (name) {
    const r = await probeTls(host, port, name, { timeout: opts.timeout });
    done++;
    emit(opts, { type: 'discovery', done: done, total: names.length, name: name, accepted: !!r.ok });
    return { name, group: groupOf(name), result: r };
  });
  const accepted = [];
  const rejected = [];
  for (const item of results) {
    if (!item || item.error) {
      rejected.push({ name: item && item.name ? item.name : '?', error: item ? item.error : 'probe failed' });
      continue;
    }
    const r = item.result;
    const rec = {
      name: item.name,
      group: item.group,
      latencyMs: r.ok ? round(r.latencyMs, 1) : null,
      protocol: r.ok ? r.protocol : null,
      alpn: r.ok ? r.alpn : null,
      leafCn: r.ok && r.leaf ? r.leaf.cn : null,
      leafFingerprint256: r.ok && r.leaf ? r.leaf.fingerprint256 : null,
      issuerCn: r.ok && r.leaf ? r.leaf.issuerCn : null,
      verified: r.ok ? r.verified : null,
      keyExchange: r.ok ? r.keyExchange : null,
      error: r.ok ? null : r.errorCode || r.error
    };
    if (r.ok) accepted.push(rec);
    else rejected.push({ name: item.name, error: rec.error });
  }
  return { accepted, rejected };
}

/** Stage 2/3: reference comparison and forward verification for one name. */
async function deepAnalyze(host, port, rec, opts, ctx) {
  const name = rec.name;
  const out = Object.assign({}, rec);
  log(opts.verbose, 'deep: ' + name);
  emit(opts, { type: 'deep-start', name: name, index: ctx.deepIndex, total: ctx.deepTotal });

  // Stability across repeated handshakes.
  const stab = await probeTlsStable(host, port, name, {
    repeat: opts.repeat,
    gap: opts.gap,
    timeout: opts.timeout
  });
  out.stability = {
    attempts: stab.attempts,
    ok: stab.ok,
    failed: stab.failed,
    successRate: round(stab.successRate, 2),
    latencyMs: {
      min: round(stab.latencyMs.min, 1),
      median: round(stab.latencyMs.median, 1),
      max: round(stab.latencyMs.max, 1)
    },
    uniqueFingerprints: stab.uniqueFingerprints,
    deterministic: stab.deterministic,
    protocols: stab.protocols,
    errors: stab.errors
  };
  const sample = stab.samples.find(function (s) {
    return s.ok;
  });
  if (sample) {
    out.via = {
      protocol: sample.protocol,
      cipher: sample.cipher,
      keyExchange: sample.keyExchange,
      alpn: sample.alpn,
      latencyMs: round(sample.latencyMs, 1),
      leaf: sample.leaf,
      chain: sample.chain,
      verified: sample.verified
    };
    out.verified = sample.verified;
    out.leaf = sample.leaf;
    out.fingerprint256 = sample.leaf ? sample.leaf.fingerprint256 : null;
    out.validityDaysLeft = sample.leaf ? daysLeft(sample.leaf.validTo) : null;
  }

  // TLS capabilities, for parity comparison with the real site.
  const v = await import('./probe.js').then(function (m) {
    return m.probeVersions(host, port, name, { timeout: opts.timeout });
  });
  out.versions = v;

  if (!opts.reference) return out;

  // Where does the real name live?
  const res = await resolveHost(name, { timeout: opts.timeout, cache: opts.cache });
  let addr = pickAddress(res, [host]);
  let referenceIsNode = false;
  if (!addr && res.addresses.length) {
    addr = res.addresses[0];
    referenceIsNode = addr === host;
  }
  out.resolution = {
    source: res.source,
    addresses: res.addresses,
    fakeIp: res.fakeIp,
    chosen: addr,
    referenceIsNode: referenceIsNode,
    errors: res.errors
  };

  if (!addr) {
    out.forward = {
      attempted: false,
      error: 'could not resolve ' + name + ' independently of the node; run with a reachable DoH resolver'
    };
    return out;
  }

  // Reference handshake against the real endpoint.
  const refProbe = await probeTls(addr, 443, name, { timeout: opts.timeout });
  out.reference = {
    address: addr,
    ok: refProbe.ok,
    latencyMs: refProbe.ok ? round(refProbe.latencyMs, 1) : null,
    protocol: refProbe.ok ? refProbe.protocol : null,
    leafFingerprint256: refProbe.ok && refProbe.leaf ? refProbe.leaf.fingerprint256 : null,
    issuerCn: refProbe.ok && refProbe.leaf ? refProbe.leaf.issuerCn : null,
    keyExchange: refProbe.ok ? refProbe.keyExchange : null,
    verified: refProbe.ok ? refProbe.verified : null,
    error: refProbe.ok ? null : refProbe.errorCode || refProbe.error
  };
  ctx.referenceFingerprint = out.reference.leafFingerprint256;
  ctx.referenceGroups = out.reference.keyExchange ? out.reference.keyExchange.name : null;

  out.forward = await verifyForward(host, port, name, addr, out, opts);
  return out;
}

/** Stage 3: hold the request constant, vary only the path, compare byte-for-byte. */
async function verifyForward(host, port, name, refAddr, deep, opts) {
  const out = { attempted: true, url: 'https://' + name + '/', differences: [] };
  const viaPin = { address: host, port: port, servername: name };
  const refPin = { address: refAddr, port: 443, servername: name };

  const via = await requestFollow(out.url, function () {
    return viaPin;
  }, { timeout: opts.timeout, followRedirects: opts.followRedirects });

  out.via = via.ok
    ? {
        status: via.status,
        bytes: via.bytes,
        bodyHash: via.bodyHash,
        ttfbMs: round(via.ttfbMs, 1),
        httpVersion: via.httpVersion,
        server: via.headers.server || null,
        hops: via.hops,
        leafFingerprint256: via.tls ? via.tls.leafFingerprint256 : null,
        alpn: via.tls ? via.tls.alpn : null
      }
    : { error: via.errorCode || via.error };

  if (!via.ok) {
    out.error = 'request through the node failed: ' + (via.errorCode || via.error);
    return out;
  }

  const ref = await requestFollow(out.url, function () {
    return refPin;
  }, { timeout: opts.timeout, followRedirects: opts.followRedirects });

  out.direct = ref.ok
    ? {
        status: ref.status,
        bytes: ref.bytes,
        bodyHash: ref.bodyHash,
        ttfbMs: round(ref.ttfbMs, 1),
        httpVersion: ref.httpVersion,
        server: ref.headers.server || null,
        hops: ref.hops
      }
    : { error: ref.errorCode || ref.error };

  if (!ref.ok) {
    out.error = 'request to the real site failed: ' + (ref.errorCode || ref.error);
    return out;
  }

  const sameStatus = via.status === ref.status;
  const sameBytes = via.bytes === ref.bytes;
  const sameHash = via.bodyHash === ref.bodyHash;
  const sameChain = deep.fingerprint256 && deep.reference && deep.reference.leafFingerprint256
    ? deep.fingerprint256 === deep.reference.leafFingerprint256
    : null;

  out.identityMatch = sameHash;
  out.comparable = sameStatus && sameBytes;
  out.leafFingerprintMatch = sameChain;
  // Machine identifiers, not sentences: the renderer turns these into prose in the
  // requested locale, and a JSON consumer can act on them without parsing English.
  out.verdicts = {
    status: sameStatus ? 'match' : 'differ',
    bytes: sameBytes ? 'match' : 'differ',
    bodyHash: sameHash ? 'identical' : 'differ',
    leafFingerprint: sameChain === null ? 'not-comparable' : sameChain ? 'identical' : 'differ'
  };
  if (!sameStatus) out.differences.push(msg('difference.status'));
  if (!sameBytes) out.differences.push(msg('difference.bytes', { n: Math.abs(via.bytes - ref.bytes) }));
  if (sameBytes && !sameHash) out.differences.push(msg('difference.content'));
  if (sameChain === false) out.differences.push(msg('difference.certificate'));

  // Static assets settle the question when the landing page is personalised or dynamic.
  if (opts.assets && opts.assets.length) {
    out.assets = [];
    for (const asset of opts.assets) {
      const u = new URL(asset, out.url).toString();
      const a = await requestPinned(u, viaPin, { timeout: opts.timeout });
      const b = await requestPinned(u, refPin, { timeout: opts.timeout });
      const entry = {
        path: asset,
        via: a.ok ? { status: a.status, bytes: a.bytes, hash: a.bodyHash } : { error: a.errorCode || a.error },
        direct: b.ok ? { status: b.status, bytes: b.bytes, hash: b.bodyHash } : { error: b.errorCode || b.error },
        identical: !!(a.ok && b.ok && a.bodyHash === b.bodyHash)
      };
      out.assets.push(entry);
      if (!entry.identical) {
        out.differences.push(msg('difference.asset', { path: asset }));
        if (out.identityMatch === true) out.identityMatch = false;
      }
    }
    const allAssetsIdentical = out.assets.every(function (x) {
      return x.identical;
    });
    out.assetsAllIdentical = out.assets.length > 0 && allAssetsIdentical;
  }
  return out;
}

/** Score one candidate. Higher is a better cover identity. */
export function scoreCandidate(c, ctx) {
  const comps = [];
  let score = 0;
  function add(points, reason) {
    score += points;
    comps.push({ points: points, reason: reason });
  }
  const v = c.verified || {};
  const genuine = !!(v.ok && v.anchored);

  if (genuine) add(35, msg('score.certGenuine'));
  else add(-25, msg('score.certForged'));

  const refFp = ctx && ctx.referenceFingerprint;
  const fpMatch = refFp && c.fingerprint256 ? refFp === c.fingerprint256 : null;
  if (fpMatch === true) add(20, msg('score.fpMatch'));
  else if (fpMatch === false) add(-20, msg('score.fpDiffer'));
  else add(0, msg('score.fpUnknown'));

  const f = c.forward || {};
  if (f.identityMatch === true) add(25, msg('score.forwardIdentical'));
  else if (f.comparable) add(10, msg('score.forwardComparable'));
  else if (f.attempted && f.error) add(-10, msg('score.forwardError'));
  else add(-5, msg('score.forwardNone'));

  const st = c.stability || {};
  if (st.successRate === 1) add(5, msg('score.stableAll'));
  else if (st.successRate >= 0.8) add(1, msg('score.stableMost', { rate: st.successRate }));
  else add(-10, msg('score.unstable', { rate: st.successRate }));

  if (st.deterministic) add(5, msg('score.deterministic'));
  else add(-10, msg('score.varying'));

  const d = c.validityDaysLeft;
  if (d != null && d > 180) add(5, msg('score.validLong', { days: d }));
  else if (d != null && d > 30) add(2, msg('score.validShort', { days: d }));
  else if (d != null) add(-10, msg('score.expiring', { days: d }));

  const refG = ctx && ctx.referenceGroups;
  const viaG = c.via && c.via.keyExchange ? c.via.keyExchange.name : null;
  if (refG && viaG) {
    if (refG === viaG) add(5, msg('score.groupMatch', { group: refG }));
    else add(-5, msg('score.groupDiffer', { via: viaG, reference: refG }));
  }

  return { score: score, grade: gradeOf(score), components: comps };
}

// Returns a machine identifier, never a translated word: the renderer owns the wording,
// and downstream consumers (JSON, tests, other tools) compare against a stable id.
export function gradeOf(score) {
  if (score >= 80) return 'excellent';
  if (score >= 60) return 'good';
  if (score >= 40) return 'fair';
  return 'poor';
}

/** Full analysis for a single node. */
export async function analyzeNode(node, options) {
  const opts = normalizeOptions(options);
  const host = node.address || node.host || node.target;
  if (!host) throw new Error('node address is required');
  const port = node.port || opts.port;
  const started = Date.now();

  const result = {
    schemaVersion: 1,
    kind: 'sni-recon',
    node: { address: host, port: port, label: node.label || host },
    startedAt: new Date(started).toISOString(),
    options: {
      timeout: opts.timeout,
      concurrency: opts.concurrency,
      repeat: opts.repeat,
      reference: opts.reference,
      serverNames: opts.serverNames,
      candidates: opts.serverNames.length ? null : 'builtin',
      fast: opts.fast,
      regional: opts.regional,
      assets: opts.assets
    }
  };

  // --- Control probes -------------------------------------------------------
  emit(opts, { type: 'phase', phase: 'controls', message: msg('progress.controls') });
  log(opts.verbose, 'baseline probe (no SNI)');
  const baseline = await probeNoSni(host, port, { timeout: opts.timeout });
  const strict = await probeTls(host, port, STRICT_NAME, { timeout: opts.timeout });
  const randomName = 'sni-recon-' + Math.random().toString(36).slice(2, 10) + '.invalid';
  const random = await probeTls(host, port, randomName, { timeout: opts.timeout });
  result.controls = {
    noSni: baseline.ok
      ? {
          ok: true,
          latencyMs: round(baseline.latencyMs, 1),
          leafCn: baseline.leaf ? baseline.leaf.cn : null,
          fingerprint256: baseline.leaf ? baseline.leaf.fingerprint256 : null,
          issuerCn: baseline.leaf ? baseline.leaf.issuerCn : null,
          anchored: !!(baseline.verified && baseline.verified.anchored),
          error: null
        }
      : { ok: false, error: baseline.errorCode || baseline.error },
    strictName: {
      name: STRICT_NAME,
      ok: !!strict.ok,
      leafCn: strict.ok && strict.leaf ? strict.leaf.cn : null,
      fingerprint256: strict.ok && strict.leaf ? strict.leaf.fingerprint256 : null,
      error: strict.ok ? null : strict.errorCode || strict.error
    },
    randomName: {
      name: randomName,
      ok: !!random.ok,
      leafCn: random.ok && random.leaf ? random.leaf.cn : null,
      fingerprint256: random.ok && random.leaf ? random.leaf.fingerprint256 : null,
      error: random.ok ? null : random.errorCode || random.error
    }
  };

  if (!baseline.ok && !strict.ok) {
    emit(opts, { type: 'unreachable', message: baseline.errorCode || baseline.error });
    result.reachable = false;
    result.finishedAt = new Date().toISOString();
    result.summary = {
      verdict: 'unreachable',
      message: msg('unreachable.message', { error: baseline.errorCode || baseline.error })
    };
    return result;
  }

  // --- Stage 1: whitelist mapping ------------------------------------------
  const names = dedupeNames(candidatesFor(opts));
  emit(opts, { type: 'phase', phase: 'discovery', message: msg('progress.discovery', { count: names.length }), total: names.length });
  log(opts.verbose, 'probing ' + names.length + ' candidate names on ' + host + ':' + port);
  const wl = await probeWhitelist(host, port, names, opts);

  const acceptedByFp = new Map();
  for (const a of wl.accepted) {
    const key = a.leafFingerprint256 || 'none';
    if (!acceptedByFp.has(key)) acceptedByFp.set(key, []);
    acceptedByFp.get(key).push(a.name);
  }
  const genericIdentity =
    wl.accepted.length > 0 &&
    wl.accepted.every(function (a) {
      return a.leafFingerprint256 === wl.accepted[0].leafFingerprint256;
    }) &&
    (!strict.ok || strict.leaf.fingerprint256 === wl.accepted[0].leafFingerprint256) &&
    (!random.ok || random.leaf.fingerprint256 === wl.accepted[0].leafFingerprint256);

  const genuineNames = wl.accepted.filter(function (a) {
    return a.verified && a.verified.ok && a.verified.anchored;
  });
  const lookalikeNames = wl.accepted.filter(function (a) {
    return !(a.verified && a.verified.ok && a.verified.anchored);
  });

  result.whitelist = {
    mode: opts.serverNames.length ? 'configured' : 'discovery',
    tested: names.length,
    accepted: wl.accepted.length,
    rejected: wl.rejected.length,
    acceptedNames: wl.accepted.map(function (a) {
      return a.name;
    }),
    rejectedSample: wl.rejected.slice(0, 40),
    genuineNames: genuineNames.map(function (a) {
      return a.name;
    }),
    lookalikeNames: lookalikeNames.map(function (a) {
      return a.name;
    }),
    distinctIdentities: acceptedByFp.size,
    genericIdentity: genericIdentity,
    strictProbeAccepted: !!strict.ok,
    randomNameAccepted: !!random.ok,
    // RealiTLScanner-style tools send SNI "invalid2.invalid" and require the returned CN
    // to match. On a whitelisted node that probe fails even though the node is healthy.
    realitlscannerCompatible: !!strict.ok
  };

  if (wl.accepted.length === 0) {
    result.reachable = true;
    result.summary = {
      verdict: 'no-candidate-accepted',
      message: msg('noCandidates.message', { tested: names.length }),
      bestName: null
    };
    result.finishedAt = new Date().toISOString();
    return result;
  }

  // --- Stage 2/3: deep analysis of the most promising names -----------------
  let deepList = wl.accepted.slice();
  deepList.sort(function (a, b) {
    const ag = a.verified && a.verified.ok && a.verified.anchored ? 0 : 1;
    const bg = b.verified && b.verified.ok && b.verified.anchored ? 0 : 1;
    if (ag !== bg) return ag - bg;
    return (a.latencyMs || 1e9) - (b.latencyMs || 1e9);
  });
  if (deepList.length > opts.maxDeep) {
    result.whitelist.deepLimitedTo = opts.maxDeep;
    deepList = deepList.slice(0, opts.maxDeep);
  }

  const ctx = { deepTotal: deepList.length };
  const analysed = [];
  if (opts.deep) {
    emit(opts, { type: 'phase', phase: 'deep', message: msg('progress.deep', { count: deepList.length }), total: deepList.length });
    ctx.deepIndex = 0;
    for (const rec of deepList) {
      ctx.deepIndex++;
      const done = await deepAnalyze(host, port, rec, opts, ctx);
      const liveScore = scoreCandidate(done, {
        referenceFingerprint: done.reference ? done.reference.leafFingerprint256 : null,
        referenceGroups: done.reference && done.reference.keyExchange ? done.reference.keyExchange.name : null
      });
      done.score = liveScore.score;
      done.grade = liveScore.grade;
      done.scoreComponents = liveScore.components;
      analysed.push(done);
      emit(opts, {
        type: 'deep-done',
        name: rec.name,
        index: ctx.deepIndex,
        total: ctx.deepTotal,
        score: done.score,
        genuine: !!(done.verified && done.verified.ok)
      });
      emit(opts, { type: 'candidate', candidate: done });
    }
  } else {
    for (const rec of deepList) analysed.push(rec);
  }

  for (const c of analysed) {
    const sc = scoreCandidate(c, { referenceFingerprint: c.reference ? c.reference.leafFingerprint256 : null, referenceGroups: c.reference ? (c.reference.keyExchange ? c.reference.keyExchange.name : null) : null });
    c.score = sc.score;
    c.grade = sc.grade;
    c.scoreComponents = sc.components;
  }
  analysed.sort(function (a, b) {
    if (b.score !== a.score) return b.score - a.score;
    return (a.stability ? a.stability.latencyMs.median || 1e9 : 1e9) - (b.stability ? b.stability.latencyMs.median || 1e9 : 1e9);
  });

  result.candidates = analysed;
  result.ranking = analysed.map(function (c, i) {
    return { rank: i + 1, name: c.name, score: c.score, grade: c.grade };
  });
  const best = analysed[0];
  result.best = best
    ? {
        name: best.name,
        score: best.score,
        grade: best.grade,
        serverNames: [best.name],
        dest: best.name + ':443',
        reasons: best.scoreComponents
          .filter(function (x) {
            return x.points > 0;
          })
          .map(function (x) {
            return x.reason;
          })
      }
    : null;

  // --- Reference control probes --------------------------------------------
  // A catch-all certificate is only suspicious if the real service does not do the same.
  // Large CDN edges routinely answer any SNI with the site certificate; flagging that
  // would mark every genuine front-end as masked.
  const bestCandidate = analysed[0] || null;
  if (bestCandidate && bestCandidate.reference && bestCandidate.reference.address && bestCandidate.reference.ok) {
    const refAddr = bestCandidate.reference.address;
    emit(opts, { type: 'phase', phase: 'controls', message: msg('progress.catchall') });
    const refRandomName = 'sni-recon-' + Math.random().toString(36).slice(2, 10) + '.invalid';
    const refRandom = await probeTls(refAddr, 443, refRandomName, { timeout: opts.timeout });
    const ownFp = bestCandidate.reference.leafFingerprint256;
    const randomFp = refRandom.ok && refRandom.leaf ? refRandom.leaf.fingerprint256 : null;
    result.referenceControls = {
      address: refAddr,
      name: bestCandidate.name,
      randomName: refRandomName,
      randomNameAccepted: !!refRandom.ok,
      ownFingerprint: ownFp,
      randomFingerprint: randomFp,
      // true => the real site itself returns its own certificate for a name it cannot own
      servesCatchAll: !!(refRandom.ok && randomFp && ownFp && randomFp === ownFp)
    };
  }

  // --- Operator identification and masking verdict --------------------------
  if (opts.hoster) {
    emit(opts, { type: 'phase', phase: 'hoster', message: msg('progress.hoster') });
    log(opts.verbose, 'identifying operator of ' + host);
    const nodeHoster = await lookupHoster(host, { timeout: opts.timeout, cache: opts.cache, verbose: opts.verbose });
    let referenceHoster = null;
    const refAddr = best && best.reference ? best.reference.address : null;
    if (refAddr && refAddr !== host) {
      referenceHoster = await lookupHoster(refAddr, { timeout: opts.timeout, cache: opts.cache, verbose: opts.verbose });
    }
    result.hoster = nodeHoster
      ? {
          ok: nodeHoster.ok,
          asn: nodeHoster.asn,
          asName: nodeHoster.asName,
          org: nodeHoster.org,
          isp: nodeHoster.isp,
          country: nodeHoster.country,
          countryCode: nodeHoster.countryCode,
          city: nodeHoster.city,
          ptr: nodeHoster.ptr,
          hosting: nodeHoster.hosting,
          proxy: nodeHoster.proxy,
          warnings: nodeHoster.warnings
        }
      : null;
    result.masking = evaluateMasking({
      nodeHoster: nodeHoster,
      referenceHoster: referenceHoster,
      controls: Object.assign({}, result.controls, { genericIdentity: genericIdentity }),
      candidates: analysed,
      genericIdentity: genericIdentity,
      referenceControls: result.referenceControls || null
    });
  }

  result.reachable = true;
  result.finishedAt = new Date().toISOString();
  result.summary = buildSummary(result);
  return result;
}

function buildSummary(result) {
  const wl = result.whitelist;
  const best = result.best;
  const s = {
    verdict: 'ok',
    bestName: best ? best.name : null,
    bestScore: best ? best.score : null,
    bestGrade: best ? best.grade : null,
    notes: []
  };
  if (wl.genericIdentity) {
    s.notes.push(msg('note.genericIdentity'));
  }
  if (!wl.strictProbeAccepted) {
    s.notes.push(msg('note.strictRejected'));
  }
  if (wl.lookalikeNames.length && !wl.genuineNames.length) {
    s.notes.push(msg('note.allLookalike'));
  }
  if (best && best.grade === 'poor') {
    s.notes.push(msg('note.weakCover'));
  }
  if (result.masking) {
    s.masking = {
      detected: result.masking.masking,
      method: result.masking.method,
      confidence: result.masking.confidence,
      verdict: result.masking.verdict
    };
    // The headline is rendered in full by the masking section of the report, so it is not
    // repeated as a note.
  }
  if (result.redaction && result.redaction.fields > 0) {
    s.notes.push(msg('note.redacted'));
  }
  return s;
}

/** Analyse several nodes concurrently. */
export async function analyzeNodes(nodes, options) {
  const opts = normalizeOptions(options);
  const results = [];
  for (const n of nodes) {
    results.push(await analyzeNode(n, opts));
  }
  return { schemaVersion: 1, kind: 'sni-recon-multi', count: results.length, nodes: results };
}
