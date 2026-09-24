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
import { sameOperator, describeHoster } from './hoster.js';

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
        'the node serves ' +
          forgedNames.length +
          ' name(s) with a certificate that does not chain to a public trust store (' +
          forgedNames.slice(0, 3).join(', ') +
          '); issuer "' +
          ((example.leaf && example.leaf.issuerCn) || 'unknown') +
          '"'
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
        'the node serves one certificate for every name, but so does the real service (' +
          (refControls.name || 'the reference host') +
          ' answers an undeclared name with the same certificate) \u2014 this is CDN edge behaviour, not masking'
      )
    );
  } else if (generic) {
    evidence.push(
      ev(
        'single-certificate-for-all-names',
        2,
        'the same certificate is returned for every SNI tested, including names the node cannot own \u2014 the signature of a catch-all reverse proxy rather than a real service'
      )
    );
  }
  if (controls.randomName && controls.randomName.ok) {
    evidence.push(
      ev(
        'accepts-undeclared-names',
        1,
        'a random undeclared name (' + controls.randomName.name + ') completes a handshake, so name-based routing is not enforced'
      )
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
        'the node relays byte-identical content for ' +
          (c.name ? '"' + c.name + '"' : 'the whitelisted name') +
          ' while the address is not operated by the domain\u2019s own provider'
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
          'the node runs on ' +
            describeHoster(nodeHoster) +
            ', while the real service runs on ' +
            describeHoster(referenceHoster) +
            ' \u2014 different operators'
        )
      );
    } else if (sameOp === true) {
      evidence.push(
        ev('operator-match', -2, 'node and the real service are operated by the same organisation (' + describeHoster(nodeHoster) + ')')
      );
    }
  }
  if (nodeHoster && nodeHoster.ok && nodeHoster.hosting === true) {
    evidence.push(
      ev('node-is-datacenter', 1, 'the address belongs to a hosting/datacenter provider, not to the domain\u2019s own network (' + describeHoster(nodeHoster) + ')')
    );
  }

  // --- Transport-level tells -----------------------------------------------
  if (best && best.reference && best.via && best.reference.ok) {
    const refG = best.reference.keyExchange ? best.reference.keyExchange.name : null;
    const viaG = best.via.keyExchange ? best.via.keyExchange.name : null;
    if (refG && viaG && refG !== viaG) {
      evidence.push(
        ev('tls-parameters-differ', 1, 'the node negotiates a different key exchange group (' + viaG + ') than the real service (' + refG + ')')
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
          anchored
            ? 'the certificate is validly issued but is not the one the site serves on its own infrastructure'
            : 'the certificate presented is not the one the real service serves, and it is not publicly trusted'
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

  const headline = headlineFor(verdict, method, confidence);

  return {
    masking: masking,
    method: method,
    confidence: confidence,
    verdict: verdict,
    headline: headline,
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

function headlineFor(verdict, method, confidence) {
  switch (verdict) {
    case 'identified-by-forged-certificate':
      return 'Hoster-level domain masking: the node mints certificates for a domain it does not own.';
    case 'identified-by-transparent-forward':
      return 'Hoster-level domain masking: the node relays for a domain it does not own.';
    case 'identified-by-generic-certificate':
      return 'Hoster-level domain masking: one catch-all certificate is served for every name.';
    case 'identified-by-content-substitution':
      return 'Hoster-level domain masking: the node serves content that does not match the real service while running on unrelated infrastructure.';
    case 'possible-forward-operator-unknown':
      return 'Possible domain masking: the node relays for another domain, but the operator could not be identified.';
    case 'genuine-front':
      return 'No masking detected: the node behaves as the domain\u2019s own infrastructure.';
    case 'suspicious':
      return 'Masking indicators present, but below the confidence threshold for a verdict.';
    default:
      return 'Inconclusive: not enough signals to judge whether a domain is being masked.';
  }
}

/** Compact one-line summary used by the TUI banner and the text report. */
export function maskingLine(m) {
  if (!m) return 'masking: unknown';
  const tag = m.masking ? 'MASKING DETECTED' : m.verdict === 'genuine-front' ? 'no masking' : 'unclear';
  return tag + ' \u00b7 ' + m.method + ' \u00b7 confidence ' + m.confidence;
}
