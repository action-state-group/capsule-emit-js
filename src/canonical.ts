// SPDX-License-Identifier: Apache-2.0
/**
 * JCS-N canonicalization: normalize → JCS → SHA-256 → lowercase hex.
 *
 * Implements algorithm jcs-n per draft-mih-sokolov-scitt-payload-binding-00 §3.1
 * and the Agent Action Capsule capsule_id derivation per
 * draft-mih-scitt-agent-action-capsule-02 §5.1.
 *
 * JSON-DIGEST := HEX(SHA-256(JCS(normalize(v))))
 */
import { createHash } from 'node:crypto';

export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER; // 2^53 - 1 = 9007199254740991

export class FloatInDigestError extends Error {
  constructor(message = 'JSON floating-point value in a digest-bearing field; §3.1 forbids this') {
    super(message);
    this.name = 'FloatInDigestError';
  }
}

export class UnsafeIntegerError extends Error {
  constructor(value: number) {
    super(
      `integer ${value} is outside the safe range +/-${MAX_SAFE_INTEGER}; ` +
      'represent large integers as exact decimal strings (§3.1)',
    );
    this.name = 'UnsafeIntegerError';
  }
}

/** Absent-field normalization (§3.1 step 1): remove, bottom-up, any object member
 *  whose value is JSON null, an empty array, or an empty object. Returns a copy. */
export function normalize(v: unknown): unknown {
  if (v === null) return null;
  if (Array.isArray(v)) {
    return (v as unknown[]).map(normalize);
  }
  if (typeof v === 'object' && v !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(v as Record<string, unknown>)) {
      const nv = normalize(val);
      if (nv === null) continue;
      if (Array.isArray(nv) && (nv as unknown[]).length === 0) continue;
      if (typeof nv === 'object' && nv !== null && !Array.isArray(nv) &&
          Object.keys(nv as object).length === 0) continue;
      out[key] = nv;
    }
    return out;
  }
  return v;
}

function _jcsString(s: string): string {
  // RFC 8785 §3.2.2.2: minimal escaping, two-char shortcuts, \u00XX for controls.
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') { out += '\\"'; }
    else if (ch === '\\') { out += '\\\\'; }
    else if (code === 0x08) { out += '\\b'; }
    else if (code === 0x09) { out += '\\t'; }
    else if (code === 0x0a) { out += '\\n'; }
    else if (code === 0x0c) { out += '\\f'; }
    else if (code === 0x0d) { out += '\\r'; }
    else if (code < 0x20) { out += `\\u${code.toString(16).padStart(4, '0')}`; }
    else { out += ch; }
  }
  return out + '"';
}

function _jcsValue(v: unknown): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'string') return _jcsString(v);
  if (typeof v === 'number') {
    if (!Number.isInteger(v) || Object.is(v, -0)) {
      // -0 serializes as "0" in JSON but we flag floats; -0 from JSON.parse is 0
      // anyway. Guard non-integer (float) inputs.
      if (!Number.isInteger(v)) throw new FloatInDigestError();
      // -0 is safe to serialize as 0; fall through to integer path.
    }
    if (v > MAX_SAFE_INTEGER || v < -MAX_SAFE_INTEGER) {
      throw new UnsafeIntegerError(v);
    }
    // Handle -0: serialize as "0"
    return Object.is(v, -0) ? "0" : String(v);
  }
  if (Array.isArray(v)) {
    return '[' + (v as unknown[]).map(_jcsValue).join(',') + ']';
  }
  if (typeof v === 'object' && v !== null) {
    // RFC 8785 §3.2.3: sort object members by UTF-16 code units of the key.
    // JavaScript's default string sort uses UTF-16 code unit comparison.
    const keys = Object.keys(v as Record<string, unknown>).sort();
    return (
      '{' +
      keys.map(k => _jcsString(k) + ':' + _jcsValue((v as Record<string, unknown>)[k])).join(',') +
      '}'
    );
  }
  throw new TypeError(`value of type ${typeof v} is not JSON-serializable in JCS context`);
}

/** RFC 8785 JCS serialization of v as a UTF-8 Buffer (no normalization applied). */
export function jcs(v: unknown): Buffer {
  return Buffer.from(_jcsValue(v), 'utf-8');
}

/** JSON-DIGEST: lowercase-hex SHA-256 of JCS(normalize(v)). */
export function jsonDigest(v: unknown): string {
  return createHash('sha256').update(jcs(normalize(v))).digest('hex');
}

/** CANONICAL-DIGEST(jcs-n, payload minus exclusion_set).
 *  Exclusion applies to top-level keys of the payload object only.
 *  Used by CPB derive_id and by capsule_id derivation. */
export function canonicalDigest(
  v: unknown,
  exclusionSet?: Set<string> | string[] | readonly string[],
): string {
  let payload = v;
  if (exclusionSet && typeof v === 'object' && v !== null && !Array.isArray(v)) {
    const excl = new Set(exclusionSet);
    if (excl.size > 0) {
      const filtered: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(v as Record<string, unknown>)) {
        if (!excl.has(key)) filtered[key] = val;
      }
      payload = filtered;
    }
  }
  return jsonDigest(payload);
}

// Fields excluded from the canonical capsule form (§5.1).
export const CHAIN_LINKAGE_FIELDS = new Set(['capsule_id', 'chain']);

/** Recompute capsule_id (§5.1): JSON-DIGEST of the envelope minus capsule_id
 *  and chain-linkage fields, after absent-field normalization. */
export function computeCapsuleId(capsule: Record<string, unknown>): string {
  if (typeof capsule !== 'object' || capsule === null || Array.isArray(capsule)) {
    throw new TypeError('capsule must be a JSON object');
  }
  const canonical: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(capsule)) {
    if (!CHAIN_LINKAGE_FIELDS.has(k)) canonical[k] = v;
  }
  return jsonDigest(canonical);
}
