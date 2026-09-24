// Domain-masking detection.
//
// The question this answers: is the host *presenting a domain it does not own* — either
// by minting certificates for it, by transparently relaying to the real site behind a
// generic certificate, or by fronting a single default certificate for every name?
//
// That is what a hosting panel calls a "masking domain". It is a property of how the
// node was configured, and it is visible from outside through three independent channels:
// the trustworthiness of the certificate, the operator behind the address, and whether
// the byte stream actually originates from the real site.
//
// Evidence is recorded as message values (key + parameters), not as English prose, so the
// same verdict renders in any shipped locale. Verdicts and method ids are stable machine
// identifiers and are never translated.
import { sameOperator, describeHoster } from './hoster.js';
import { msg } from './messages.js';

export const METHOD = {
  FORGED: 'forged-certificate',
  FORWARD: 'transparent-forward',
  GENERIC: 'generic-default-certificate',
  NONE: 'none'
};

function ev(signal, weight, detail) {
  return { signal: signal, weight: weight, detail: detail };
}

/**
 * Build the masking verdict for one node.
 *
 * @param {object} input
 * @param {object} input.nodeHoster   result of lookupHoster() for the node address
 * @param {object} input.controls     the control-probe block from analyzeNode()
 * @param {Array}  input.candidates   deep-analysed candidates
 * @param {object} input.referenceHoster hoster info for the real site of the best candidate
 */
export function evaluateMasking(input) {
  const nodeHoster = input.nodeHoster || null;
  const controls = input.controls || {};
  const candidates = input.candidates || [];
  const referenceHoster = input.referenceHoster || null;

  const evidence = [];
  const best = candidates[0] || null;
  // Consider every name that was actually handshake-probed. Certificates come from the
  // discovery stage, so masking must still be judged when --no-deep skips the detail pass;
  // forward-verification checks below simply have nothing to compare in that case.
  const deep = candidates.filter(function (c) {
    return c && c.verified;
  });

  // --- Channel 1: is the certificate honestly issued for the name? -----------
  // Any name the node answers with a certificate that is not anchored in a public
  // trust store is a forged identity: the node is claiming a domain it cannot prove.
  const forged = deep.filter(function (c) {
    return c.verified && !c.verified.ok && !c.verified.anchored;
  });
  const forgedNames = forged.map(function (c) {
    return c.name;
  });
  if (forgedNames.length) {
    const example = forged[0];
    evidence.push(
      ev(
        'untrusted-certificate-for-foreign-domain',
        3,
        msg('evidence.untrusted-certificate-for-foreign-domain', {
          count: forgedNames.length,
          names: forgedNames.slice(0, 3).join(', '),
          issuer: (example.leaf && example.leaf.issuerCn) || 'unknown'
        })
      )
    );
  }

  // --- Channel 2: does one certificate cover every name? ---------------------
  const refControls = input.referenceControls || null;
  // If the genuine service also answers any SNI with its own certificate, this behaviour
  // is the upstream's, not the host's, and carries no information about masking.
  const genericIsUpstream = !!(refControls && refControls.servesCatchAll);
  const generic = controls.genericIdentity === true || input.genericIdentity === true;
  if (generic && genericIsUpstream) {
    evidence.push(
      ev(
        'catch-all-certificate-is-upstream',
        0,
        msg('evidence.catch-all-certificate-is-upstream', {
          name: (refControls && refControls.name) || 'the reference host'
        })
      )
    );
  } else if (generic) {
    evidence.push(ev('single-certificate-for-all-names', 2, msg('evidence.single-certificate-for-all-names')));
  }
  if (controls.randomName && controls.randomName.ok) {
    evidence.push(
      ev('accepts-undeclared-names', 1, msg('evidence.accepts-undeclared-names', { name: controls.randomName.name }))
    );
  }

  // --- Channel 3: does the byte stream come from the real site? -------------
  const identical = deep.filter(function (c) {
    return c.forward && c.forward.identityMatch === true;
  });
  const differing = deep.filter(function (c) {
    return c.forward && c.forward.attempted && !c.forward.error && c.forward.identityMatch === false;
  });
  let method = METHOD.NONE;

  if (forgedNames.length) {
    method = METHOD.FORGED;
  } else if (identical.length) {
    method = METHOD.FORWARD;
    const c = identical[0];
    evidence.push(
      ev(
        'content-served-from-elsewhere',
        2,
        msg('evidence.content-served-from-elsewhere', { name: c.name || '' })
      )
    );
  } else if (generic && !genericIsUpstream) {
    method = METHOD.GENERIC;
  } else if (differing.length) {
    method = METHOD.FORWARD;
  }

  // --- Operator comparison --------------------------------------------------
  let sameOp = null;
  if (nodeHoster && nodeHoster.ok && referenceHoster && referenceHoster.ok) {
    sameOp = sameOperator(nodeHoster, referenceHoster);
    if (sameOp === false) {
      evidence.push(
        ev(
          'operator-mismatch',
          2,
          msg('evidence.operator-mismatch', { node: nodeHoster, reference: referenceHoster })
        )
      );
    } else if (sameOp === true) {
      evidence.push(
        ev('operator-match', -2, msg('evidence.operator-match', { node: nodeHoster }))
      );
    }
  }
  if (nodeHoster && nodeHoster.ok && nodeHoster.hosting === true) {
    evidence.push(
      ev('node-is-datacenter', 1, msg('evidence.node-is-datacenter', { node: nodeHoster }))
    );
  }

  // --- Transport-level tells -----------------------------------------------
  if (best && best.reference && best.via && best.reference.ok) {
    const refG = best.reference.keyExchange ? best.reference.keyExchange.name : null;
    const viaG = best.via.keyExchange ? best.via.keyExchange.name : null;
    if (refG && viaG && refG !== viaG) {
      evidence.push(
        ev('tls-parameters-differ', 1, msg('evidence.tls-parameters-differ', { via: viaG, reference: refG }))
      );
    }
    const refFp = best.reference.leafFingerprint256;
    const viaFp = best.fingerprint256;
    if (refFp && viaFp && refFp !== viaFp && forgedNames.length === 0) {
      const anchored = best.verified && best.verified.anchored;
      evidence.push(
        ev(
          'certificate-differs-from-real-site',
          anchored ? 1 : 3,
          msg(anchored ? 'evidence.certificate-differs-anchored' : 'evidence.certificate-differs-untrusted')
        )
      );
    }
  }

  const weight = evidence.reduce(function (s, e) {
    return s + e.weight;
  }, 0);
  const positive = evidence.filter(function (e) {
    return e.weight > 0;
  });

  let masking = false;
  let confidence = 'low';
  let verdict = 'genuine-front';

  // Order matters. A forged certificate is masking no matter who operates the address.
  // But when the certificate is honestly issued AND the address is run by the same
  // organisation as the real service, this simply *is* that service: reporting masking
  // there would be a false positive on every legitimate front-end.
  if (method === METHOD.FORGED) {
    masking = true;
    confidence = 'high';
    verdict = 'identified-by-forged-certificate';
  } else if (sameOp === true && method !== METHOD.GENERIC) {
    masking = false;
    confidence = 'high';
    verdict = 'genuine-front';
  } else if (method === METHOD.FORWARD && sameOp === false) {
    masking = true;
    confidence = identical.length ? 'high' : 'medium';
    verdict = 'identified-by-transparent-forward';
  } else if (method === METHOD.FORWARD) {
    masking = true;
    confidence = 'low';
    verdict = 'possible-forward-operator-unknown';
  } else if (method === METHOD.GENERIC) {
    masking = true;
    confidence = 'medium';
    verdict = 'identified-by-generic-certificate';
  } else if (differing.length && sameOp === false) {
    masking = true;
    confidence = 'medium';
    verdict = 'identified-by-content-substitution';
  } else {
    verdict = weight >= 2 ? 'suspicious' : 'inconclusive';
    masking = weight >= 3;
  }

  return {
    masking: masking,
    method: method,
    confidence: confidence,
    verdict: verdict,
    // Message value, not a string: the renderer owns the wording and the language.
    headline: msg('masking.headline.' + verdict),
    // The clause alone, used inside the framed section whose title it would otherwise
    // repeat. The full sentence stays in `headline` for prose contexts.
    reasoning: msg('masking.reasoning.' + verdict),
    weight: weight,
    positiveSignals: positive.length,
    sameOperator: sameOp,
    nodeHoster: nodeHoster
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
          description: describeHoster(nodeHoster),
          warnings: nodeHoster.warnings
        }
      : null,
    referenceHoster: referenceHoster && referenceHoster.ok
      ? { asn: referenceHoster.asn, org: referenceHoster.org, description: describeHoster(referenceHoster) }
      : null,
    evidence: evidence
  };
}

/** Compact one-line summary used by the TUI banner and the text report. */
export function maskingLine(m, t) {
  if (!m) return t ? t('misc.unknown') : 'unknown';
  const tag = m.masking
    ? t
      ? t('masking.detected')
      : 'masking'
    : m.verdict === 'genuine-front'
    ? t
      ? t('masking.notDetected')
      : 'no masking'
    : t
    ? t('masking.inconclusive')
    : 'unclear';
  return tag + ' · ' + (t ? t('method.' + m.method) : m.method) + ' · ' + (t ? t('confidence.' + m.confidence) : m.confidence);
}

export default { evaluateMasking, maskingLine, METHOD };
