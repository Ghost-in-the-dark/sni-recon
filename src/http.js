// IP-pinned HTTP client.
//
// Every request is sent to a chosen address while carrying an independent Host header and
// SNI, which is what lets us hold the network path constant and vary only the identity
// the node is asked to present. Redirects, compression and byte-exact body capture are
// handled locally so responses stay comparable.
import https from 'node:https';
import http from 'node:http';
import zlib from 'node:zlib';
import { URL } from 'node:url';
import { UA, sha256Hex, hrMs, errText, isIp } from './util.js';
import { cnOf } from './cert.js';

function decompress(buf, encoding) {
  const enc = String(encoding || '').toLowerCase();
  try {
    if (enc.indexOf('br') !== -1) return zlib.brotliDecompressSync(buf);
    if (enc.indexOf('gzip') !== -1) return zlib.gunzipSync(buf);
    if (enc.indexOf('deflate') !== -1) return zlib.inflateSync(buf);
  } catch (e) {
    return null;
  }
  return buf;
}

/**
 * One pinned request. `pin` = { address, port, servername }.
 * Never rejects; transport failures come back as { ok: false, error }.
 */
export function requestPinned(urlStr, pin, opts) {
  const options = opts || {};
  const u = new URL(urlStr);
  const secure = u.protocol === 'https:';
  const mod = secure ? https : http;
  const port = pin.port || (secure ? 443 : 80);
  const timeout = options.timeout == null ? 12000 : options.timeout;
  const maxBytes = options.maxBytes == null ? 4 * 1024 * 1024 : options.maxBytes;
  const method = options.method || 'GET';
  const started = hrMs();

  const headers = Object.assign(
    {
      host: options.hostHeader || u.host,
      'user-agent': options.userAgent || UA,
      accept: options.accept || '*/*',
      'accept-encoding': options.acceptEncoding === false ? 'identity' : 'gzip, deflate, br',
      connection: 'close'
    },
    options.headers || {}
  );

  const reqOpts = {
    host: pin.address,
    port: port,
    method: method,
    path: u.pathname + u.search,
    headers: headers,
    agent: false,
    timeout: timeout,
    rejectUnauthorized: false,
    checkServerIdentity: function () {
      return undefined;
    }
  };
  if (secure && pin.servername && !isIp(pin.servername)) reqOpts.servername = pin.servername;
  if (options.alpn) reqOpts.ALPNProtocols = options.alpn;
  if (options.minVersion) reqOpts.minVersion = options.minVersion;
  if (options.maxVersion) reqOpts.maxVersion = options.maxVersion;
  if (options.family) reqOpts.family = options.family;

  return new Promise(function (resolve) {
    let settled = false;
    let req = null;
    function done(o) {
      if (settled) return;
      settled = true;
      try {
        if (req) req.destroy();
      } catch (e) {
        /* ignore */
      }
      resolve(o);
    }
    try {
      req = mod.request(reqOpts, function (res) {
        const ttfbMs = hrMs() - started;
        const chunks = [];
        let n = 0;
        let aborted = false;
        res.on('data', function (c) {
          n += c.length;
          if (n > maxBytes) {
            aborted = true;
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        res.on('end', function () {
          const raw = Buffer.concat(chunks);
          const dec = decompress(raw, res.headers['content-encoding']);
          const body = dec === null ? raw : dec;
          let tlsInfo = null;
          try {
            const sock = res.socket || (req.socket || null);
            if (sock && typeof sock.getPeerCertificate === 'function') {
              const leaf = sock.getPeerX509Certificate ? sock.getPeerX509Certificate() : null;
              tlsInfo = {
                protocol: typeof sock.getProtocol === 'function' ? sock.getProtocol() : null,
                alpn: sock.alpnProtocol || null,
                leafFingerprint256: leaf ? leaf.fingerprint256 : null,
                leafCn: leaf ? cnOf(leaf.subject) : null,
                authorized: sock.authorized === true
              };
            }
          } catch (e) {
            /* ignore */
          }
          done({
            ok: true,
            url: urlStr,
            status: res.statusCode,
            statusText: res.statusMessage || '',
            headers: res.headers,
            rawBytes: raw.length,
            bytes: body.length,
            bodyHash: sha256Hex(body),
            body: body,
            truncated: aborted,
            ttfbMs: ttfbMs,
            totalMs: hrMs() - started,
            httpVersion: res.httpVersion,
            address: pin.address,
            servername: reqOpts.servername || null,
            tls: tlsInfo
          });
        });
        res.on('error', function (e) {
          done({ ok: false, url: urlStr, error: errText(e), errorCode: e.code || null, address: pin.address });
        });
      });
    } catch (e) {
      done({ ok: false, url: urlStr, error: errText(e), errorCode: e.code || null, address: pin.address });
      return;
    }
    req.on('timeout', function () {
      done({ ok: false, url: urlStr, error: 'timeout after ' + timeout + 'ms', errorCode: 'ETIMEDOUT', address: pin.address });
    });
    req.on('error', function (e) {
      done({ ok: false, url: urlStr, error: errText(e), errorCode: e.code || null, address: pin.address });
    });
    req.end();
  });
}

/** Follow up to `maxRedirects` hops manually, keeping the pin (or re-pinning per host). */
export async function requestFollow(urlStr, pinFor, opts) {
  const options = opts || {};
  const maxRedirects = options.maxRedirects == null ? 3 : options.maxRedirects;
  const hops = [];
  let current = urlStr;
  for (let i = 0; i <= maxRedirects; i++) {
    const pin = typeof pinFor === 'function' ? await pinFor(current) : pinFor;
    if (!pin) return { ok: false, error: 'no address for ' + current, hops: hops };
    const r = await requestPinned(current, pin, options);
    r.hops = undefined;
    hops.push({
      url: current,
      status: r.status,
      location: r.headers && r.headers.location ? r.headers.location : null,
      bytes: r.bytes,
      bodyHash: r.bodyHash
    });
    if (!r.ok) {
      r.hops = hops;
      return r;
    }
    const loc = r.headers && r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc && options.followRedirects !== false) {
      current = new URL(loc, current).toString();
      continue;
    }
    r.hops = hops;
    return r;
  }
  return { ok: false, error: 'too many redirects', hops: hops };
}

/** TEXT status line for reporting. */
export function statusLine(r) {
  if (!r || !r.ok) return 'ERR ' + ((r && (r.errorCode || r.error)) || 'unknown');
  return String(r.status) + ' ' + (r.statusText || '');
}
