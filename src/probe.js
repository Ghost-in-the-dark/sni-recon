// Raw TLS probing: handshake, certificate capture, ALPN, key exchange group, and latency sampling.
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import { hrMs, isIp, errText, median, sleep, pool } from './util.js';
import { chainRaw, x509, verifyChain, certSummary, aiaIssuersUrls } from './cert.js';

export const DEFAULT_ALPN = ['h2', 'http/1.1'];

/**
 * One TLS handshake against (host, port) with an explicit SNI. Never rejects:
 * failures come back as { ok: false, error, errorCode }.
 */
export function probeTls(host, port, servername, opts) {
  const options = opts || {};
  const timeout = options.timeout == null ? 8000 : options.timeout;
  const started = hrMs();
  return new Promise(function (resolve) {
    let settled = false;
    let socket = null;
    function done(obj) {
      if (settled) return;
      settled = true;
      try {
        if (socket) socket.destroy();
      } catch (e) {
        /* ignore */
      }
      resolve(obj);
    }
    const connectOpts = {
      host: host,
      port: port,
      rejectUnauthorized: false,
      checkServerIdentity: function () {
        return undefined;
      },
      ALPNProtocols: options.alpn === null ? undefined : options.alpn || DEFAULT_ALPN,
      timeout: timeout,
      family: options.family || 0
    };
    // An IP literal must never be sent as SNI (RFC 6066 forbids it); omit it so the
    // peer behaves exactly as it would for a default client.
    if (servername && !isIp(servername)) connectOpts.servername = servername;
    if (options.minVersion) connectOpts.minVersion = options.minVersion;
    if (options.maxVersion) connectOpts.maxVersion = options.maxVersion;
    if (options.ciphers) connectOpts.ciphers = options.ciphers;
    if (options.sigalgs) connectOpts.sigalgs = options.sigalgs;

    try {
      socket = tls.connect(connectOpts);
    } catch (e) {
      done({ ok: false, error: errText(e), errorCode: e.code || null, latencyMs: hrMs() - started });
      return;
    }

    socket.once('secureConnect', function () {
      const latencyMs = hrMs() - started;
      let rawChain = [];
      let leaf = null;
      let chainCerts = [];
      try {
        const peer = socket.getPeerCertificate(true);
        rawChain = chainRaw(peer);
        if (typeof socket.getPeerX509Certificate === 'function') {
          leaf = socket.getPeerX509Certificate();
        }
        if (!leaf && rawChain.length) leaf = x509(rawChain[0]);
        chainCerts = rawChain.slice(1).map(x509).filter(Boolean);
      } catch (e) {
        /* handled below */
      }
      let ephemeral = null;
      let protocol = null;
      let cipher = null;
      try {
        protocol = socket.getProtocol();
        const c = socket.getCipher();
        cipher = c ? { name: c.name, version: c.version, standardName: c.standardName } : null;
        ephemeral = socket.getEphemeralKeyInfo();
      } catch (e) {
        /* ignore */
      }
      const info = {
        ok: true,
        host: host,
        port: port,
        servername: connectOpts.servername || null,
        sniSent: !!connectOpts.servername,
        latencyMs: latencyMs,
        protocol: protocol,
        cipher: cipher,
        keyExchange: ephemeral,
        alpn: socket.alpnProtocol || null,
        sessionReused: typeof socket.isSessionReused === 'function' ? socket.isSessionReused() : null,
        clientAuthorized: socket.authorized === true,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        leaf: certSummary(leaf),
        chain: chainCerts.map(certSummary),
        rawChainLength: rawChain.length,
        aiaUrls: aiaIssuersUrls(leaf)
      };
      info.verified = verifyChain(leaf, chainCerts, connectOpts.servername || null);
      done(info);
    });

    socket.once('timeout', function () {
      done({ ok: false, error: 'timeout after ' + timeout + 'ms', errorCode: 'ETIMEDOUT', latencyMs: hrMs() - started });
    });
    socket.once('error', function (e) {
      done({
        ok: false,
        error: errText(e),
        errorCode: e.code || null,
        latencyMs: hrMs() - started,
        servername: connectOpts.servername || null
      });
    });
  });
}

/** Open the socket with no SNI at all, to observe default-certificate behaviour. */
export function probeNoSni(host, port, opts) {
  const options = opts || {};
  const connectOpts = {
    host: host,
    port: port,
    rejectUnauthorized: false,
    checkServerIdentity: function () {
      return undefined;
    },
    timeout: options.timeout == null ? 8000 : options.timeout
  };
  if (options.alpn !== null) connectOpts.ALPNProtocols = options.alpn || DEFAULT_ALPN;
  const started = hrMs();
  return new Promise(function (resolve) {
    let settled = false;
    let socket = null;
    function done(o) {
      if (settled) return;
      settled = true;
      try {
        if (socket) socket.destroy();
      } catch (e) {
        /* ignore */
      }
      resolve(o);
    }
    try {
      socket = tls.connect(connectOpts);
    } catch (e) {
      done({ ok: false, error: errText(e), errorCode: e.code || null });
      return;
    }
    socket.once('secureConnect', function () {
      let leaf = null;
      let chainCerts = [];
      try {
        const peer = socket.getPeerCertificate(true);
        chainCerts = chainRaw(peer).slice(1).map(x509).filter(Boolean);
        if (typeof socket.getPeerX509Certificate === 'function') leaf = socket.getPeerX509Certificate();
        if (!leaf) leaf = x509(chainRaw(peer)[0]);
      } catch (e) {
        /* ignore */
      }
      done({
        ok: true,
        latencyMs: hrMs() - started,
        sniSent: false,
        leaf: certSummary(leaf),
        chain: chainCerts.map(certSummary),
        verified: verifyChain(leaf, chainCerts, null)
      });
    });
    socket.once('timeout', function () {
      done({ ok: false, error: 'timeout', errorCode: 'ETIMEDOUT' });
    });
    socket.once('error', function (e) {
      done({ ok: false, error: errText(e), errorCode: e.code || null });
    });
  });
}

/** Repeat one handshake N times to measure stability and certificate determinism. */
export async function probeTlsStable(host, port, servername, opts) {
  const options = opts || {};
  const n = Math.max(1, options.repeat || 5);
  const gap = options.gap == null ? 120 : options.gap;
  const results = [];
  for (let i = 0; i < n; i++) {
    results.push(await probeTls(host, port, servername, options));
    if (i < n - 1 && gap) await sleep(gap);
  }
  const oks = results.filter(function (r) {
    return r.ok;
  });
  const fps = oks.map(function (r) {
    return r.leaf && r.leaf.fingerprint256;
  });
  const uniqueFps = Array.from(new Set(fps.filter(Boolean)));
  const lat = oks.map(function (r) {
    return r.latencyMs;
  });
  const protocols = Array.from(
    new Set(
      oks.map(function (r) {
        return r.protocol;
      })
    )
  );
  return {
    attempts: n,
    ok: oks.length,
    failed: n - oks.length,
    successRate: oks.length / n,
    latencyMs: { min: lat.length ? Math.min.apply(null, lat) : null, median: median(lat), max: lat.length ? Math.max.apply(null, lat) : null },
    uniqueFingerprints: uniqueFps.length,
    deterministic: uniqueFps.length === 1,
    fingerprint256: uniqueFps[0] || null,
    protocols: protocols,
    errors: results
      .filter(function (r) {
        return !r.ok;
      })
      .map(function (r) {
        return r.errorCode || r.error;
      }),
    samples: results
  };
}

/** Which TLS 1.3 groups does the endpoint accept? Mirrors what an observer can measure. */
export async function probeGroups(host, port, servername, opts) {
  const candidates = [
    { id: 'X25519', group: 'x25519' },
    { id: 'X25519MLKEM768', group: 'X25519MLKEM768' },
    { id: 'P-256', group: 'prime256v1' },
    { id: 'P-384', group: 'secp384r1' }
  ];
  const out = {};
  for (const c of candidates) {
    const r = await probeTls(host, port, servername, Object.assign({}, opts, { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: c.group, sigalgs: undefined }));
    out[c.id] = r.ok ? (r.keyExchange && r.keyExchange.name) || 'accepted' : false;
  }
  return out;
}

/** Compare TLS version / cipher acceptance between the node and a reference. */
export async function probeVersions(host, port, servername, opts) {
  const matrix = [
    { v: 'TLSv1.3', min: 'TLSv1.3', max: 'TLSv1.3' },
    { v: 'TLSv1.2', min: 'TLSv1.2', max: 'TLSv1.2' }
  ];
  const out = {};
  for (const m of matrix) {
    const r = await probeTls(host, port, servername, Object.assign({}, opts, { minVersion: m.min, maxVersion: m.max }));
    out[m.v] = r.ok ? { ok: true, cipher: r.cipher && r.cipher.standardName } : { ok: false, error: r.errorCode || r.error };
  }
  return out;
}

/** Fetch a DER certificate over plain HTTP (used for AIA intermediate chasing). */
export function fetchDer(url, timeout) {
  return new Promise(function (resolve) {
    let req;
    const opts = { timeout: timeout || 6000, headers: { accept: '*/*' } };
    function onRes(res) {
      const chunks = [];
      let n = 0;
      res.on('data', function (c) {
        n += c.length;
        if (n > 1 << 20) {
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on('end', function () {
        resolve({ ok: true, status: res.statusCode, body: Buffer.concat(chunks) });
      });
    }
    try {
      if (url.indexOf('http://') === 0) req = http.get(url, opts, onRes);
      else req = https.get(url, opts, onRes);
    } catch (e) {
      resolve({ ok: false, error: errText(e) });
      return;
    }
    req.on('timeout', function () {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });
    req.on('error', function (e) {
      resolve({ ok: false, error: errText(e) });
    });
  });
}
