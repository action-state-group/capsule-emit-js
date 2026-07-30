// SPDX-License-Identifier: Apache-2.0
/**
 * Class 1 verifier (AAC §6). Never throws; returns a structured VerificationResult.
 * Implements draft-mih-scitt-agent-action-capsule-02 §6.
 */
import {
  FloatInDigestError,
  UnsafeIntegerError,
  MAX_SAFE_INTEGER,
  computeCapsuleId,
} from './canonical.js';
import {
  NEVER_DISPATCH_VERDICT_CLASSES,
  VALID_APPROVERS,
  LEDGER_MODE_RANK,
  DOMAIN_VALUES,
  PROVENANCE_VALUES,
  deriveEffectMode,
  isHex64,
} from './contracts.js';
import { REGISTRIES } from './registries.js';

export interface Finding {
  code: string;
  detail: string;
  severity: 'error' | 'warning' | 'info';
  check: number | null;
}

export interface VerificationResult {
  ok: boolean;
  findings: Finding[];
  assurance: Record<string, string>;
  capsule_id: string | null;
}

const REQUIRED_FIELDS = [
  'spec_version', 'format_version', 'capsule_id', 'action_id',
  'action_type', 'operator', 'developer', 'timestamp',
];

const _EFFECT_MODE_RANK: Record<string, number> = {
  not_applicable: 0, dispatched_unconfirmed: 0, confirmed: 1,
};
const _ATTESTATION_RANK: Record<string, number> = { self_attested: 0, anchored: 1 };

const _REGISTRY_FIELDS: Array<[string, [string, string]]> = [
  ['verdict_class',          ['disposition', 'verdict_class']],
  ['disposition.decision',   ['disposition', 'decision']],
  ['effect.type',            ['effect', 'type']],
  ['irreversibility_class',  ['effect', 'irreversibility_class']],
  ['effect_attestation',     ['effect', 'effect_attestation']],
  ['chain.relation',         ['chain', 'relation']],
];

function _obj(capsule: Record<string, unknown>, key: string): Record<string, unknown> | null {
  const v = capsule[key];
  return (typeof v === 'object' && v !== null && !Array.isArray(v))
    ? v as Record<string, unknown>
    : null;
}

function _floatPaths(v: unknown, path = ''): string[] {
  const out: string[] = [];
  if (typeof v === 'boolean') return out;
  if (typeof v === 'number' && !Number.isInteger(v)) return [path || '<root>'];
  if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out.push(..._floatPaths(val, path ? `${path}.${k}` : k));
    }
  } else if (Array.isArray(v)) {
    for (let i = 0; i < (v as unknown[]).length; i++) {
      out.push(..._floatPaths((v as unknown[])[i], `${path}[${i}]`));
    }
  }
  return out;
}

function _unsafeIntPaths(v: unknown, path = ''): string[] {
  const out: string[] = [];
  if (typeof v === 'boolean') return out;
  if (typeof v === 'number' && Number.isInteger(v)) {
    if (v > MAX_SAFE_INTEGER || v < -MAX_SAFE_INTEGER) return [path || '<root>'];
    return out;
  }
  if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out.push(..._unsafeIntPaths(val, path ? `${path}.${k}` : k));
    }
  } else if (Array.isArray(v)) {
    for (let i = 0; i < (v as unknown[]).length; i++) {
      out.push(..._unsafeIntPaths((v as unknown[])[i], `${path}[${i}]`));
    }
  }
  return out;
}

function _storeIds(store: unknown[]): Set<string> {
  const ids = new Set<string>();
  for (const item of store) {
    if (typeof item === 'object' && item !== null) {
      const cid = (item as Record<string, unknown>)['capsule_id'];
      if (typeof cid === 'string') ids.add(cid);
    } else if (typeof item === 'string') {
      ids.add(item);
    }
  }
  return ids;
}

function _finding(
  code: string, detail: string,
  severity: 'error' | 'warning' | 'info' = 'error',
  check: number | null = null,
): Finding {
  return { code, detail, severity, check };
}

function _verify(
  capsule: unknown,
  store: unknown[] | null,
  registries: Record<string, Set<string>>,
): VerificationResult {
  const findings: Finding[] = [];

  if (typeof capsule !== 'object' || capsule === null || Array.isArray(capsule)) {
    findings.push(_finding('not_an_object', 'Capsule is not a JSON object', 'error', 1));
    return { ok: false, findings, assurance: {}, capsule_id: null };
  }

  const cap = capsule as Record<string, unknown>;
  const effect = _obj(cap, 'effect');
  const disposition = _obj(cap, 'disposition');
  const chain = _obj(cap, 'chain');

  // ---- Check 1: Structural ------------------------------------------------
  for (const fld of REQUIRED_FIELDS) {
    if (!(fld in cap)) {
      findings.push(_finding('missing_required_field', `${fld} is REQUIRED (§5.1)`, 'error', 1));
    } else if (typeof cap[fld] !== 'string') {
      findings.push(_finding('field_not_string', `${fld} MUST be a string (§5.1)`, 'error', 1));
    }
  }
  const cid = cap['capsule_id'];
  if (cid !== undefined && !isHex64(cid)) {
    findings.push(_finding('capsule_id_malformed', 'capsule_id MUST be 64 lowercase hex (§5.1)', 'error', 1));
  }
  const at = cap['action_type'];
  if (at !== undefined && at !== 'fyi' && at !== 'decide') {
    findings.push(_finding('action_type_invalid', "action_type MUST be 'fyi' or 'decide' (§5.1)", 'error', 1));
  }
  const fv = cap['format_version'];
  if (typeof fv === 'string' && fv !== '2') {
    findings.push(_finding(
      'unsupported_format_version',
      `format_version ${JSON.stringify(fv)} is not a supported version; only "2" is defined (§5.1); ` +
      'unknown versions must be explicitly rejected to prevent silent v1/v2 mis-parse',
      'error', 1,
    ));
  }
  for (const fld of ['effect', 'assurance', 'disposition', 'chain', 'self_reported_reasoning']) {
    const val = cap[fld];
    if (val !== undefined && (typeof val !== 'object' || val === null || Array.isArray(val))) {
      findings.push(_finding('block_not_object', `${fld} MUST be a JSON object when present`, 'error', 1));
    }
  }
  for (const fld of ['domain', 'provenance']) {
    const val = cap[fld];
    if (val !== undefined && typeof val !== 'string') {
      findings.push(_finding(`${fld}_not_string`, `${fld} MUST be a string when present (§-02)`, 'error', 1));
    }
  }
  const cons = cap['constraints'];
  if (cons !== undefined && !Array.isArray(cons)) {
    findings.push(_finding('constraints_not_array', 'constraints MUST be an array when present (§8.1)', 'error', 1));
  }
  for (const p of _floatPaths(cap)) {
    findings.push(_finding('float_in_digest_field', `floating-point value at ${p}; §5.1 forbids it`, 'error', 1));
  }
  for (const p of _unsafeIntPaths(cap)) {
    findings.push(_finding(
      'unsafe_integer_in_digest_field',
      `integer outside the JS-safe range (+/-${MAX_SAFE_INTEGER}) at ${p}; ` +
      'large integers MUST be exact decimal strings for cross-impl digest reproducibility (impl guard ahead of -00; see -01 flag)',
      'error', 1,
    ));
  }
  // Disposition structural checks + honesty.
  if (disposition !== null) {
    const approver = disposition['approver'];
    if (approver === undefined || approver === null) {
      findings.push(_finding('missing_required_field', 'disposition.approver is REQUIRED (§5.4)', 'error', 1));
    } else if (!VALID_APPROVERS.has(approver as string)) {
      findings.push(_finding(
        'approver_invalid',
        `disposition.approver MUST be human|policy (§5.4); got ${JSON.stringify(approver)}`,
        'error', 1,
      ));
    }
    if (!('decision' in disposition)) {
      findings.push(_finding('missing_required_field', 'disposition.decision is REQUIRED (§5.4)', 'error', 1));
    }
    const hd = disposition['human_disposed'];
    if (typeof hd !== 'boolean') {
      findings.push(_finding('field_not_bool', 'disposition.human_disposed is REQUIRED and boolean (§5.4)', 'error', 1));
    } else if (hd === true && approver !== 'human') {
      findings.push(_finding(
        'dishonest_human_disposed',
        'human_disposed=true with a non-human approver (§5.4). Structurally unconstructable by a conforming producer; ' +
        'reported as a non-gating defensive warning, not a §6 gating check.',
        'warning', null,
      ));
    }
  }

  // ---- Check 2: Identity --------------------------------------------------
  let recomputed: string | null = null;
  if (isHex64(cid)) {
    try {
      recomputed = computeCapsuleId(cap);
    } catch (e) {
      if (!(e instanceof FloatInDigestError) && !(e instanceof UnsafeIntegerError)) {
        findings.push(_finding('capsule_id_uncomputable', String(e), 'error', 2));
      }
      // FloatInDigestError / UnsafeIntegerError already reported in check 1
    }
    if (recomputed !== null && recomputed !== cid) {
      findings.push(_finding(
        'capsule_id_mismatch',
        `recomputed ${recomputed} != carried ${cid as string}`,
        'error', 2,
      ));
    }
  }

  // ---- Check 3: Confirmed-effect binding ----------------------------------
  if (effect !== null && effect['status'] === 'confirmed' && !isHex64(effect['response_digest'])) {
    findings.push(_finding(
      'confirmed_without_response',
      "effect.status 'confirmed' requires a 64-hex response_digest (§5.2)",
      'error', 3,
    ));
  }

  const effectMode = deriveEffectMode(effect);

  // ---- Check 4: Verdict/effect orthogonality ------------------------------
  const verdictClass = disposition !== null ? (disposition['verdict_class'] as string | undefined) : undefined;
  if (verdictClass && NEVER_DISPATCH_VERDICT_CLASSES.has(verdictClass) && effectMode !== 'not_applicable') {
    findings.push(_finding(
      'verdict_effect_conflict',
      `verdict_class '${verdictClass}' never dispatches, but derived effect_mode is '${effectMode}' (§5.4.2)`,
      'error', 4,
    ));
  }

  // ---- Check 5: Effect-attestation matrix ---------------------------------
  const ea = effect !== null ? effect['effect_attestation'] : undefined;
  if (effectMode === 'confirmed' || effectMode === 'dispatched_unconfirmed') {
    if (ea === undefined || ea === null) {
      findings.push(_finding(
        'effect_attestation_missing',
        `effect_attestation REQUIRED for effect_mode '${effectMode}' (§5.2)`,
        'error', 5,
      ));
    }
  } else {
    if (ea !== undefined && ea !== null) {
      findings.push(_finding(
        'effect_attestation_present',
        "effect_attestation MUST be absent for effect_mode 'not_applicable' (§5.2)",
        'error', 5,
      ));
    }
  }

  // ---- Check 6: Chain semantics (store-level) -----------------------------
  if (chain !== null) {
    const parent = chain['parent_capsule_id'];
    if (!isHex64(parent)) {
      findings.push(_finding(
        'chain_parent_malformed',
        'chain.parent_capsule_id MUST be a 64-hex capsule_id (§5.4.4)',
        'error', 6,
      ));
    }
    if (!('relation' in chain)) {
      findings.push(_finding(
        'missing_required_field',
        'chain.relation is REQUIRED when a chain block is present (§5.4.4)',
        'error', 6,
      ));
    }
    if (store === null) {
      findings.push(_finding(
        'chain_check_store_level',
        'chain parent-existence and concurrent-supersedes are store-level checks (§6); not run without a store',
        'info', 6,
      ));
    } else {
      const ids = _storeIds(store);
      if (typeof parent === 'string' && !ids.has(parent)) {
        findings.push(_finding(
          'chain_parent_missing',
          `chain parent ${parent} not found in the store (§6)`,
          'error', 6,
        ));
      }
    }
  }

  // ---- Check 7: Assurance reconciliation ----------------------------------
  const derived: Record<string, string> = {
    effect_mode: effectMode,
    attestation_mode: 'self_attested',
    ledger_mode: chain !== null ? 'chained' : 'standalone',
  };
  const statedAssurance = _obj(cap, 'assurance');
  if (statedAssurance !== null) {
    const sm = statedAssurance['effect_mode'] as string | undefined;
    if (sm && (_EFFECT_MODE_RANK[sm] ?? -1) > (_EFFECT_MODE_RANK[effectMode] ?? 0)) {
      findings.push(_finding(
        'assurance_overclaim',
        `claimed effect_mode '${sm}' but verifier derived '${effectMode}' (§5.3)`,
        'error', 7,
      ));
    }
    const sa = statedAssurance['attestation_mode'] as string | undefined;
    if (sa && (_ATTESTATION_RANK[sa] ?? -1) > _ATTESTATION_RANK[derived['attestation_mode']]) {
      findings.push(_finding(
        'assurance_overclaim',
        `claimed attestation_mode '${sa}' but no Receipt verified at this layer (§5.3)`,
        'info', 7,
      ));
    }
    const sl = statedAssurance['ledger_mode'] as string | undefined;
    if (sl && (LEDGER_MODE_RANK[sl] ?? -1) > (LEDGER_MODE_RANK[derived['ledger_mode']] ?? 0)) {
      findings.push(_finding(
        'assurance_overclaim',
        `claimed ledger_mode '${sl}' but verifier derived '${derived['ledger_mode']}' (§5.3)`,
        'info', 7,
      ));
    }
  }

  // ---- Check 8: Unknown registry values -----------------------------------
  for (const [regName, [block, member]] of _REGISTRY_FIELDS) {
    const blk = _obj(cap, block);
    if (blk === null) continue;
    const val = blk[member];
    if (val === undefined || val === null) continue;
    const seeded = registries[regName] ?? new Set<string>();
    if (!seeded.has(val as string)) {
      findings.push(_finding(
        'unknown_registry_value',
        `${block}.${member}=${JSON.stringify(val)} is not a seeded ${regName} value; informational, not rejected (§12)`,
        'info', 8,
      ));
      if (regName === 'effect_attestation') {
        findings.push(_finding(
          'effect_attestation_graded_floor',
          "unknown effect_attestation graded no stronger than 'runtime_claimed' (§5.2)",
          'info', 8,
        ));
      }
    }
  }

  // ---- Check 9: domain / provenance unknown-value (§-02) -----------------
  const domainVal = cap['domain'];
  if (typeof domainVal === 'string' && !DOMAIN_VALUES.has(domainVal) && !domainVal.startsWith('x-')) {
    findings.push(_finding(
      'domain_unknown_value',
      `domain=${JSON.stringify(domainVal)} is not a seeded value; informational, not rejected (§-02 REGISTRY §8)`,
      'info', null,
    ));
  }
  const provenanceVal = cap['provenance'];
  if (typeof provenanceVal === 'string' && !PROVENANCE_VALUES.has(provenanceVal) && !provenanceVal.startsWith('x-')) {
    findings.push(_finding(
      'provenance_unknown_value',
      `provenance=${JSON.stringify(provenanceVal)} is not a seeded value; informational, not rejected (§-02 REGISTRY §9)`,
      'info', null,
    ));
  }

  const ok = !findings.some(f => f.severity === 'error');
  return { ok, findings, assurance: derived, capsule_id: recomputed };
}

/** Run Class 1 verification (§6) over a single Capsule. Never throws. */
export function verify(
  capsule: unknown,
  store: unknown[] | null = null,
  registries: Record<string, Set<string>> = REGISTRIES,
): VerificationResult {
  try {
    return _verify(capsule, store, registries);
  } catch (e) {
    return {
      ok: false,
      findings: [{ code: 'verifier_internal_error', detail: String(e), severity: 'error', check: null }],
      assurance: {},
      capsule_id: null,
    };
  }
}

/** Verify a ledger of Capsules, running store-level chain checks (§6/§5.4.4). */
export function verifyStore(
  capsules: unknown[],
  registries: Record<string, Set<string>> = REGISTRIES,
): VerificationResult[] {
  const results = capsules.map(c => verify(c, capsules, registries));
  // Concurrent-supersedes (§5.4.4): earliest is authoritative.
  const seenParent = new Set<string>();
  for (let i = 0; i < capsules.length; i++) {
    const c = capsules[i];
    if (typeof c !== 'object' || c === null || Array.isArray(c)) continue;
    const cap = c as Record<string, unknown>;
    const ch = cap['chain'];
    if (typeof ch !== 'object' || ch === null || Array.isArray(ch)) continue;
    const chainObj = ch as Record<string, unknown>;
    if (chainObj['relation'] !== 'supersedes') continue;
    const parent = chainObj['parent_capsule_id'];
    if (typeof parent !== 'string') continue;
    if (seenParent.has(parent)) {
      results[i].findings.push({
        code: 'concurrent_supersedes',
        detail: `a later supersedes over parent ${parent}; the earliest is authoritative (§5.4.4)`,
        severity: 'info',
        check: 6,
      });
    } else {
      seenParent.add(parent);
    }
  }
  return results;
}
