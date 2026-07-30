// SPDX-License-Identifier: Apache-2.0
/**
 * Rung 1 — emit(): sealed-Capsule builder with self-attestation.
 * Implements draft-mih-scitt-agent-action-capsule-02 §5.
 */
import { randomUUID } from 'node:crypto';
import { computeCapsuleId, jsonDigest } from './canonical.js';
import {
  NEVER_DISPATCH_VERDICT_CLASSES,
  VALID_APPROVERS,
  isHex64,
  InvariantError,
  deriveEffectMode,
  type DispositionInput,
  type EffectRecordInput,
  type ModelAttestationInput,
  type ConstraintRecordInput,
  type SelfReportedReasoningInput,
} from './contracts.js';

export const DEFAULT_SPEC_VERSION = 'draft-mih-scitt-agent-action-capsule-02';
export const DEFAULT_FORMAT_VERSION = '2';

export type { DispositionInput, EffectRecordInput, ModelAttestationInput, ConstraintRecordInput };

export interface EmitOptions {
  action_id?: string;
  action_type?: 'fyi' | 'decide';
  operator?: string;
  developer?: string;
  model_id?: string;
  provider?: string;
  timestamp?: string;
  compute_attestation?: Record<string, unknown>;
  effect?: EffectRecordInput;
  prior_capsule_id?: string;
  chain_relation?: string;
  disposition?: DispositionInput;
  constraints?: ConstraintRecordInput[];
  domain?: string;
  provenance?: string;
  self_reported_reasoning_digest?: string;
  spec_version?: string;
  format_version?: string;
  tool_name?: string;
}

export type Capsule = Record<string, unknown>;

function _now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function _omitNulls(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== null && v !== undefined) out[k] = v;
  }
  return out;
}

/** Build and seal a Capsule with self-attestation (§5.3).
 *  Returns the sealed dict with capsule_id computed over the canonical form (§5.1). */
export function emit(opts: EmitOptions = {}): Capsule {
  const {
    action_id,
    action_type = 'fyi',
    operator = '',
    developer = '',
    model_id,
    provider,
    timestamp,
    compute_attestation,
    effect: effectInput,
    prior_capsule_id,
    chain_relation,
    disposition: dispositionInput,
    constraints = [],
    domain,
    provenance,
    self_reported_reasoning_digest,
    spec_version = DEFAULT_SPEC_VERSION,
    format_version = DEFAULT_FORMAT_VERSION,
    tool_name,
  } = opts;

  const actionId = action_id ?? (tool_name ? `${tool_name}/${randomUUID()}` : `tool-call/${randomUUID()}`);
  const ts = timestamp ?? _now();

  // Validate disposition honesty invariant.
  if (dispositionInput) {
    const { approver, human_disposed } = dispositionInput;
    if (approver && !VALID_APPROVERS.has(approver)) {
      throw new InvariantError(`disposition.approver MUST be one of ${[...VALID_APPROVERS].sort()} (§5.4); got '${approver}'`);
    }
    if (human_disposed && approver !== 'human') {
      throw new InvariantError("human_disposed=true REQUIRES approver='human' (§5.4)");
    }
  }

  // Build model_attestation.
  let modelAtt: Record<string, unknown> | null = null;
  if (model_id !== undefined && provider !== undefined) {
    modelAtt = _omitNulls({ model_id, provider, compute_attestation: compute_attestation ?? null });
  } else if (compute_attestation !== undefined) {
    modelAtt = { compute_attestation };
  }

  // Build chain.
  let chain: Record<string, unknown> | null = null;
  if (prior_capsule_id !== undefined) {
    if (!isHex64(prior_capsule_id)) {
      throw new InvariantError('chain.parent_capsule_id MUST be a 64-hex capsule_id (§5.4.4)');
    }
    const rel = chain_relation ?? (tool_name ? 'sequence' : 'follows');
    chain = { parent_capsule_id: prior_capsule_id, relation: rel };
  }

  // Build effect record.
  let effectRecord: Record<string, unknown> | null = null;
  if (effectInput !== undefined) {
    const eff = { ...effectInput };
    // Auto-derive effect_attestation if missing for dispatched/confirmed/failed/reverted.
    if (!eff.effect_attestation && ['dispatched', 'confirmed', 'failed', 'reverted'].includes(eff.status)) {
      eff.effect_attestation = 'runtime_claimed';
    }
    effectRecord = _omitNulls(eff as Record<string, unknown>);
  }

  // Validate never-dispatch invariant.
  if (dispositionInput?.verdict_class && effectRecord) {
    const vc = dispositionInput.verdict_class;
    const es = effectRecord['status'] as string;
    if (NEVER_DISPATCH_VERDICT_CLASSES.has(vc) && ['dispatched', 'confirmed', 'failed', 'reverted'].includes(es)) {
      throw new InvariantError(
        `verdict_class '${vc}' is in NEVER_DISPATCH_VERDICT_CLASSES (§5.4.2) and is incompatible with effect.status '${es}'`,
      );
    }
  }

  const effectDict = effectRecord;
  const effectMode = deriveEffectMode(effectDict as Record<string, unknown> | null);
  const ledgerMode = chain ? 'chained' : 'standalone';

  const assurance: Record<string, unknown> = {
    attestation_mode: 'self_attested',
    effect_mode: effectMode,
    ledger_mode: ledgerMode,
  };

  // Default disposition for fyi actions.
  let disposition: Record<string, unknown> | null = null;
  if (dispositionInput) {
    disposition = _omitNulls({
      decision: dispositionInput.decision,
      approver: dispositionInput.approver,
      human_disposed: dispositionInput.human_disposed ?? false,
      authority: dispositionInput.authority ?? null,
      verdict_class: dispositionInput.verdict_class ?? null,
      reason_digest: dispositionInput.reason_digest ?? null,
      expiry_policy: dispositionInput.expiry_policy ?? null,
    });
  } else if (action_type === 'fyi') {
    disposition = {
      decision: 'accept',
      approver: 'policy',
      human_disposed: false,
      verdict_class: 'executed',
    };
  }

  // Build self_reported_reasoning.
  let srr: Record<string, unknown> | null = null;
  if (self_reported_reasoning_digest !== undefined) {
    if (!isHex64(self_reported_reasoning_digest)) {
      throw new InvariantError('self_reported_reasoning.digest MUST be a 64-hex JSON-DIGEST (§-02)');
    }
    srr = { digest: self_reported_reasoning_digest };
  }

  // Assemble the body (order matches Python parse.py to_dict() for predictability).
  const body: Record<string, unknown> = {
    spec_version,
    format_version,
    action_id: actionId,
    action_type,
    operator,
    developer,
    timestamp: ts,
  };
  if (domain !== undefined) body['domain'] = domain;
  if (provenance !== undefined) body['provenance'] = provenance;
  if (modelAtt) body['model_attestation'] = modelAtt;
  if (srr) body['self_reported_reasoning'] = srr;
  if (effectRecord) body['effect'] = effectRecord;
  body['assurance'] = assurance;
  if (disposition) body['disposition'] = disposition;
  if (constraints.length > 0) body['constraints'] = constraints.map(c => _omitNulls(c as unknown as Record<string, unknown>));
  if (chain) body['chain'] = chain;

  // Compute capsule_id and seal.
  const capsuleId = computeCapsuleId(body);
  return { spec_version, format_version, capsule_id: capsuleId, ...body };
}

/** Compute SHA-256 of JCS(normalize(v)) — for digest-committing agent I/O. */
export function digestValue(v: unknown): string {
  return jsonDigest(v);
}
