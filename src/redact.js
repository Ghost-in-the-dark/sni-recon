// Operator-detail redaction.
//
// A scan report names the hosting provider behind the node. That is useful to the operator
// and sensitive to everyone else, so it must be removable from a published report without
// losing the parts that matter: certificate verdicts, whitelist mapping and forward
// comparison are all independent of who runs the box.
//
// Redaction therefore rewrites only operator-identifying fields and leaves every verdict
// intact. It is applied AFTER analysis, so it can never change a conclusion — only how
// much of the infrastructure is disclosed.
//
// It is also deliberately NON-MUTATING. The analysis result is reachable from several
// places at once — masking evidence holds message parameters that alias the very hoster
// records the verdict was computed from — so blanking fields in place would corrupt data
// the caller still owns (including exported fixtures). A redacted copy is returned instead.

export const REDACTED = '[redacted]';

// Fields that identify the operator. Anything not listed here is provenance, not identity.
const FIELDS = ['asn', 'asName', 'org', 'isp', 'ptr', 'city', 'country', 'countryCode', 'description'];

function looksLikeHosterRecord(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  return 'asn' in v || 'asName' in v || 'org' in v || 'isp' in v;
}

/** Structural clone for plain JSON-shaped data, with a guarded fallback. */
function clonePlain(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (e) {
    return value;
  }
}

function blankFields(rec) {
  let n = 0;
  for (const f of FIELDS) {
    if (rec[f] !== undefined && rec[f] !== null && rec[f] !== REDACTED) {
      rec[f] = REDACTED;
      n++;
    }
  }
  // The datacenter flag is a property of the address class, not of the operator's name,
  // and the masking verdict leans on it — so it survives redaction.
  return n;
}

function walk(node) {
  if (!node || typeof node !== 'object') return 0;
  if (Array.isArray(node)) {
    let n = 0;
    for (const item of node) n += walk(item);
    return n;
  }
  let n = looksLikeHosterRecord(node) ? blankFields(node) : 0;
  for (const k of Object.keys(node)) {
    const v = node[k];
    if (v && typeof v === 'object') n += walk(v);
  }
  return n;
}

/**
 * Produce a redacted copy of a result.
 *
 * @returns {{ result: any, fields: number }} the redacted copy and how many fields were
 *          blanked. The input object is never modified.
 */
export function redactOperatorDetails(result) {
  if (!result || typeof result !== 'object') return { result: result, fields: 0 };
  const copy = clonePlain(result);
  const fields = walk(copy);
  return { result: copy, fields: fields };
}

export default { redactOperatorDetails, REDACTED };
