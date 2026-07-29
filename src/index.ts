// SPDX-License-Identifier: Apache-2.0
/** Agent Action Capsule — spec-pure JS/TS library. */

export {
  MAX_SAFE_INTEGER,
  FloatInDigestError,
  UnsafeIntegerError,
  normalize,
  jcs,
  jsonDigest,
  canonicalDigest,
  computeCapsuleId,
  CHAIN_LINKAGE_FIELDS,
} from './canonical.js';

export {
  isHex64,
  deriveEffectMode,
  InvariantError,
  VALID_APPROVERS,
  NEVER_DISPATCH_VERDICT_CLASSES,
  EFFECT_MODES,
  ATTESTATION_MODES,
  LEDGER_MODES,
  LEDGER_MODE_RANK,
  DOMAIN_VALUES,
  PROVENANCE_VALUES,
  PROVENANCE_RANK,
  type DispositionInput,
  type EffectRecordInput,
  type ModelAttestationInput,
  type ConstraintRecordInput,
  type AssuranceBlockInput,
  type SelfReportedReasoningInput,
} from './contracts.js';

export { REGISTRIES } from './registries.js';

export { deriveId, verifyCarriedId, CarriedIdMismatch } from './derive_id.js';

export {
  makeTypedRef,
  verifyTypedRef,
  TypedRefError,
  ContextMismatchError,
  RepresentationMismatchError,
  type ArtifactTypeRegistryEntry,
  type TypedRefFields,
} from './typed_ref.js';

export {
  emit,
  digestValue,
  DEFAULT_SPEC_VERSION,
  DEFAULT_FORMAT_VERSION,
  type EmitOptions,
  type Capsule,
} from './emit.js';

export {
  verify,
  verifyStore,
  type Finding,
  type VerificationResult,
} from './verify.js';
