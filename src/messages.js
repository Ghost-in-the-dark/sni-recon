// Message values: a key plus its parameters, resolved to text only at render time.
//
// The analysis engine never formats prose. It records *what* it found ("this signal fired,
// with these values") and the renderer decides *how* to say it, in the locale that was
// requested. Two consequences worth stating, because they are the reason for the design:
//
//   * a report can be re-rendered in another language without re-running a scan that may
//     have taken minutes;
//   * the JSON output carries structured signal keys rather than English sentences, so a
//     consumer does not have to parse prose to act on it.

/** Build a message value. */
export function msg(key, params) {
  const m = { key: key };
  if (params !== undefined && params !== null) m.params = params;
  return m;
}

export function isMsg(x) {
  return !!(x && typeof x === 'object' && typeof x.key === 'string' && (x.params === undefined || x.params === null || typeof x.params === 'object'));
}

import { describeHoster } from './hoster.js';

/**
 * A hoster record passed as a parameter, rather than a pre-formatted operator string.
 *
 * This matters for redaction: if the operator's name were baked into the message at
 * analysis time, blanking the record afterwards would not remove it from the report.
 * Keeping the record means the description is composed at render time, from whatever
 * the record holds *then*.
 */
function hasHosterShape(v) {
  return !!(v && typeof v === 'object' && ('asn' in v || 'org' in v || 'isp' in v) && !('key' in v));
}

/**
 * Turn nested message values and hoster records into plain strings for interpolation.
 *
 * A parameter may itself be a message (a nested phrase) or a hoster record (an operator
 * description, which is data rather than prose and is composed from its fields).
 */
export function stringifyParams(params, deps) {
  if (!params) return params;
  const out = {};
  for (const k of Object.keys(params)) {
    const v = params[k];
    if (isMsg(v)) out[k] = renderMsg(deps && deps.t, v, deps);
    else if (hasHosterShape(v)) out[k] = describeHoster(v);
    else out[k] = v;
  }
  return out;
}

/** Resolve one message value with a translator. Never throws on a malformed value. */
export function renderMsg(t, value, deps) {
  if (isMsg(value)) {
    // Carry the translator down so nested messages resolve in the same locale; without
    // this a message inside a parameter is silently dropped.
    const child = Object.assign({}, deps || {}, { t: t });
    return t(value.key, stringifyParams(value.params, child));
  }
  if (value === null || value === undefined) return '';
  return String(value);
}

/** Resolve an array of message values, dropping empties. */
export function renderList(t, list, deps) {
  const out = [];
  for (const item of list || []) {
    const s = renderMsg(t, item, deps);
    if (s) out.push(s);
  }
  return out;
}

export default { msg, isMsg, renderMsg, renderList, stringifyParams };
