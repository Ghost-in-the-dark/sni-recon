// X.509 helpers: naming, SAN parsing, and OFFLINE chain verification against Node's bundled trust store.
//
// The whole point of this module is to answer one question without touching the network:
// "does this certificate chain actually terminate in a publicly trusted root?"
// A node that mints its own lookalike certificate for a popular hostname fails that test,
// and no amount of successful handshakes can hide it.
import crypto from 'node:crypto';
import tls from 'node:tls';

let ROOTS = null;
let ROOT_BY_SUBJECT = null;

export function trustedRoots() {
  if (ROOTS) return ROOTS;
  ROOTS = [];
  const pems = (tls && tls.rootCertificates) || [];
  for (const pem of pems) {
    try {
      ROOTS.push(new crypto.X509Certificate(pem));
    } catch (e) {
      /* skip unparsable root */
    }
  }
  return ROOTS;
}

function rootIndex() {
  if (ROOT_BY_SUBJECT) return ROOT_BY_SUBJECT;
  ROOT_BY_SUBJECT = new Map();
  for (const r of trustedRoots()) {
    const key = normDn(r.subject);
    if (!ROOT_BY_SUBJECT.has(key)) ROOT_BY_SUBJECT.set(key, []);
    ROOT_BY_SUBJECT.get(key).push(r);
  }
  return ROOT_BY_SUBJECT;
}

export function isTrustedRoot(c) {
  if (!c || !c.fingerprint256) return false;
  for (const r of trustedRoots()) {
    if (r.fingerprint256 === c.fingerprint256) return true;
  }
  return false;
}

export function dnString(dn) {
  if (!dn) return '';
  if (typeof dn === 'object') {
    return Object.keys(dn)
      .map(function (k) {
        return k + '=' + dn[k];
      })
      .join('\n');
  }
  return String(dn);
}

// Order-independent, stable representation of a distinguished name, so that
// "C=US\nO=X\nCN=Y" and "CN=Y,O=X,C=US" compare equal.
export function normDn(dn) {
  let parts = dnString(dn).split('\n');
  // Node renders subjects newline-separated; OpenSSL and RFC 2253 use commas.
  // Only fall back to comma splitting when there are no newlines, so that a value
  // which legitimately contains a comma is not torn apart.
  if (parts.length === 1 && parts[0].indexOf(',') !== -1) parts = parts[0].split(',');
  return parts
    .map(function (s) {
      return s.trim();
    })
    .filter(Boolean)
    .sort()
    .join(',');
}

export function cnOf(dn) {
  const s = dnString(dn);
  for (const p of s.split('\n')) {
    const m = /^CN=(.*)$/.exec(p.trim());
    if (m) return m[1].trim();
  }
  const m2 = /(?:^|,\s*)CN=([^,]+)/.exec(s);
  return m2 ? m2[1].trim() : '';
}

/** True when the DN's common name equals the given value (case-insensitive). */
export function cnIs(dn, value) {
  return cnOf(dn).toLowerCase() === String(value || '').toLowerCase();
}

export function parseSans(str) {
  if (!str) return [];
  const out = [];
  for (const raw of String(str).split(/,\s*/)) {
    const it = raw.trim();
    if (!it) continue;
    const m = /^([A-Za-z ]+):(.*)$/.exec(it);
    if (!m) {
      out.push({ type: 'other', value: it });
      continue;
    }
    const label = m[1].trim();
    let type = label;
    if (/^dns/i.test(label)) type = 'DNS';
    else if (/^ip/i.test(label)) type = 'IP';
    else if (/^email/i.test(label)) type = 'email';
    else if (/^uri/i.test(label)) type = 'URI';
    out.push({ type: type, value: m[2].trim() });
  }
  return out;
}

export function x509(raw) {
  try {
    return new crypto.X509Certificate(raw);
  } catch (e) {
    return null;
  }
}

export function certSummary(c) {
  if (!c) return null;
  return {
    cn: cnOf(c.subject),
    subject: normDn(c.subject),
    issuer: normDn(c.issuer),
    issuerCn: cnOf(c.issuer),
    validFrom: c.validFrom,
    validTo: c.validTo,
    fingerprint256: c.fingerprint256,
    serialNumber: c.serialNumber,
    subjectAltName: c.subjectAltName || '',
    sans: parseSans(c.subjectAltName),
    selfIssued: normDn(c.subject) === normDn(c.issuer)
  };
}

// Walk peer.issuerCertificate into a flat array, leaf first. Guard against cycles.
export function chainRaw(peer) {
  const out = [];
  const seen = new Set();
  let cur = peer;
  while (cur && cur.raw) {
    const fp = cur.fingerprint256 || 'len' + out.length;
    if (seen.has(fp)) break;
    seen.add(fp);
    out.push(cur.raw);
    cur = cur.issuerCertificate;
  }
  return out;
}

// Best-effort AIA "CA Issuers" extraction so an unsent intermediate can be fetched.
export function aiaIssuersUrls(x) {
  if (!x) return [];
  const urls = [];
  try {
    const ia = x.infoAccess;
    if (typeof ia !== 'string' || !ia) return [];
    for (const line of ia.split('\n')) {
      const m = /CA Issuers\s*-\s*URI:(\S+)/i.exec(line);
      if (m) urls.push(m[1]);
    }
  } catch (e) {
    /* infoAccess is not exposed on all Node builds */
  }
  return urls;
}

function tryVerify(child, parent) {
  if (!child || !parent) return false;
  try {
    return child.verify(parent.publicKey) === true;
  } catch (e) {
    return false;
  }
}

function tryIssuedBy(child, parent) {
  if (!child || !parent) return false;
  try {
    if (typeof child.checkIssued === 'function') return child.checkIssued(parent) === true;
  } catch (e) {
    /* fall through to DN comparison */
  }
  return normDn(child.issuer) === normDn(parent.subject);
}

function inWindow(c, at) {
  const from = Date.parse(c.validFrom);
  const to = Date.parse(c.validTo);
  if (!Number.isFinite(from) || !Number.isFinite(to)) return true; // unknown -> do not penalise
  return from <= at && at <= to;
}

/**
 * Verify a chain offline. `chain` is the list of issuer certificates, leaf EXCLUDED.
 * Returns a structured verdict; never throws.
 */
export function verifyChain(leaf, chain, host, opts) {
  const options = opts || {};
  const at = options.at || Date.now();
  const res = {
    ok: false,
    anchored: false,
    selfSigned: false,
    depth: 0,
    complete: false,
    datesOk: true,
    sigOk: true,
    hostCovered: false,
    hostMatch: null,
    anchor: null,
    inTrustStore: false,
    links: [],
    errors: []
  };
  if (!leaf) {
    res.errors.push('no leaf certificate');
    return res;
  }

  const certs = [leaf].concat(chain || []);
  res.depth = certs.length;
  res.selfSigned = normDn(leaf.subject) === normDn(leaf.issuer);

  // 1. Validity windows.
  for (const c of certs) {
    if (!inWindow(c, at)) {
      res.datesOk = false;
      res.errors.push('certificate outside validity window: ' + cnOf(c.subject) + ' (' + c.validFrom + ' .. ' + c.validTo + ')');
    }
  }

  // 2. Signature links.
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const parent = certs[i + 1];
    const issuedBy = tryIssuedBy(child, parent);
    const signed = issuedBy && tryVerify(child, parent);
    res.links.push({ from: cnOf(child.subject), to: cnOf(parent.subject), signed: signed });
    if (!signed) {
      res.sigOk = false;
      res.errors.push('signature link broken: ' + cnOf(child.subject) + ' -> ' + cnOf(parent.subject));
    }
  }

  // 3. Anchor: does the topmost certificate terminate in a publicly trusted root?
  const top = certs[certs.length - 1];
  if (isTrustedRoot(top)) {
    res.anchored = true;
    res.inTrustStore = true;
    res.anchor = certSummary(top);
    res.complete = true;
  } else if (normDn(top.subject) === normDn(top.issuer)) {
    // self-issued and NOT in the trust store: a private / self-signed root
    res.errors.push('chain terminates in a self-issued root that is not publicly trusted: ' + cnOf(top.subject));
  } else {
    const want = normDn(top.issuer);
    const pool = (rootIndex().get(want) || []).slice();
    if (top.issuerCertificate && top.issuerCertificate.raw) {
      const extra = x509(top.issuerCertificate.raw);
      if (extra) pool.push(extra);
    }
    let found = null;
    for (const r of pool) {
      if (tryVerify(top, r)) {
        found = r;
        break;
      }
    }
    if (found) {
      res.anchored = true;
      res.inTrustStore = isTrustedRoot(found);
      res.anchor = certSummary(found);
      res.complete = true;
      res.links.push({ from: cnOf(top.subject), to: cnOf(found.subject), signed: true });
    } else {
      res.errors.push(
        'chain does not terminate in a trusted root; missing or untrusted issuer: ' + (cnOf(top.issuer) || want)
      );
    }
  }

  // 4. Hostname coverage (RFC 6125 matching, including wildcards).
  if (host) {
    try {
      const m = leaf.checkHost(host);
      if (m) {
        res.hostCovered = true;
        res.hostMatch = m;
      } else {
        res.errors.push('leaf certificate does not cover ' + host);
      }
    } catch (e) {
      res.errors.push('hostname check failed for ' + host);
    }
  } else {
    res.hostCovered = true;
  }

  res.ok = res.anchored && res.datesOk && res.sigOk && res.hostCovered;
  if (options.requireAnchor === false) {
    res.ok = res.datesOk && res.sigOk && res.hostCovered;
  }
  return res;
}
