// SPDX-License-Identifier: Apache-2.0
/** Typed producer-side carriers, structural constants, and derive_effect_mode. */

export const HEX64_RE = /^[0-9a-f]{64}$/;

export function isHex64(v: unknown): v is string {
  return typeof v === 'string' && HEX64_RE.test(v);
}

export const EFFECT_STATUSES = new Set([
  'planned', 'dispatched', 'confirmed', 'failed', 'reverted',
]);

export const NEVER_DISPATCH_VERDICT_CLASSES = new Set([
  'blocked', 'hitl_dispatched', 'denied', 'engine_failure', 'deferred',
  'needs_decision', 'expired', 'escalated', 'resolved',
]);

export const VALID_APPROVERS = new Set(['human', 'policy']);

export const ATTESTATION_MODES = new Set(['self_attested', 'anchored']);
export const EFFECT_MODES = new Set(['not_applicable', 'dispatched_unconfirmed', 'confirmed']);
export const LEDGER_MODES = new Set(['standalone', 'chained', 'anchored']);
export const LEDGER_MODE_RANK: Record<string, number> = {
  standalone: 0, chained: 1, anchored: 2,
};

export const DOMAIN_VALUES = new Set(['action', 'memory', 'reasoning']);
export const PROVENANCE_VALUES = new Set(['gate', 'runtime', 'collector']);
export const PROVENANCE_RANK: Record<string, number> = { gate: 3, runtime: 2, collector: 1 };

export class InvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvariantError';
  }
}

/** Derive assurance.effect_mode from the Effect Record dict (§5.2). */
export function deriveEffectMode(effect: Record<string, unknown> | null | undefined): string {
  if (!effect) return 'not_applicable';
  const status = effect['status'];
  if (status === 'planned') return 'not_applicable';
  if (status === 'confirmed') {
    return isHex64(effect['response_digest']) ? 'confirmed' : 'dispatched_unconfirmed';
  }
  return 'dispatched_unconfirmed';
}

// ---- Typed carrier interfaces (for the emit() path) ----

export interface ExpiryPolicyInput {
  ttl_seconds: number;
  on_expiry: 'expired' | 'escalated';
}

export interface DispositionInput {
  decision: string;
  approver: 'human' | 'policy';
  human_disposed?: boolean;
  authority?: string;
  verdict_class?: string;
  reason_digest?: string;
  expiry_policy?: ExpiryPolicyInput;
}

export interface EffectRecordInput {
  status: string;
  type?: string;
  request_digest?: string;
  response_digest?: string;
  external_ref?: string;
  irreversibility_class?: string;
  effect_attestation?: string;
}

export interface ModelAttestationInput {
  model_id?: string;
  provider?: string;
  compute_attestation?: Record<string, unknown>;
}

export interface ChainInput {
  parent_capsule_id: string;
  relation: string;
}

export interface ConstraintRecordInput {
  id: string;
  result: 'pass' | 'fail' | 'n/a';
  severity?: string;
  blocking?: boolean;
  check_type?: string;
  method?: string;
  evidence_digest?: string;
}

export interface AssuranceBlockInput {
  attestation_mode: string;
  effect_mode: string;
  ledger_mode: string;
}

export interface SelfReportedReasoningInput {
  digest: string;
}
