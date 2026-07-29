// SPDX-License-Identifier: Apache-2.0
/**
 * Typed digest reference: construction and verification.
 * Reference: draft-mih-sokolov-scitt-payload-binding-00 §6.
 */
import { canonicalDigest } from './canonical.js';

const BARE_HEX_RE = /^[0-9a-f]{64}$/;
const PREFIXED_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export class TypedRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TypedRefError';
  }
}

export class ContextMismatchError extends TypedRefError {
  readonly carried: string;
  readonly recomputed: string;
  readonly artifactType: string;
  constructor(carried: string, recomputed: string, artifactType: string) {
    super(
      `recomputed digest ${recomputed} does not match carried digest ${carried} ` +
      `for artifact type '${artifactType}' (§6.1)`,
    );
    this.name = 'ContextMismatchError';
    this.carried = carried;
    this.recomputed = recomputed;
    this.artifactType = artifactType;
  }
}

export class RepresentationMismatchError extends TypedRefError {
  readonly carried: string;
  readonly expectedRepr: string;
  readonly artifactType: string;
  constructor(carried: string, expectedRepr: string, artifactType: string) {
    super(
      `carried digest '${carried}' is inconsistent with declared representation ` +
      `'${expectedRepr}' for artifact type '${artifactType}' (§6.1)`,
    );
    this.name = 'RepresentationMismatchError';
    this.carried = carried;
    this.expectedRepr = expectedRepr;
    this.artifactType = artifactType;
  }
}

export interface ArtifactTypeRegistryEntry {
  /** The artifact type name (matches the 'type' field in the TypedRef). */
  name: string;
  /** Canonicalization algorithm; currently only 'jcs-n' is registered. */
  algorithm?: string;
  /** Top-level fields excluded from the canonical form. */
  exclusion_set?: string[] | readonly string[];
  /** Digest representation: 'bare_hex' (default), 'prefixed', or 'raw'. */
  representation?: string;
}

export interface TypedRefFields {
  type: string;
  digest_alg: string;
  digest: string;
}

function _checkRepresentation(digest: string, representation: string, artifactType: string): void {
  const repr = representation || 'bare_hex';
  if (repr === 'bare_hex') {
    if (!BARE_HEX_RE.test(digest)) {
      throw new RepresentationMismatchError(
        digest, 'bare_hex (64-char lowercase hex)', artifactType,
      );
    }
  } else if (repr === 'prefixed') {
    if (!PREFIXED_HEX_RE.test(digest)) {
      throw new RepresentationMismatchError(
        digest, "prefixed ('sha256:' + 64-char lowercase hex)", artifactType,
      );
    }
  } else if (repr === 'raw') {
    if (!BARE_HEX_RE.test(digest)) {
      throw new RepresentationMismatchError(
        digest, 'raw (32 bytes as 64-char lowercase hex)', artifactType,
      );
    }
  }
}

/** Construct a typed digest reference to an artifact (§6). */
export function makeTypedRef(
  artifactPayload: Record<string, unknown>,
  registryEntry: ArtifactTypeRegistryEntry,
): TypedRefFields {
  const digest = canonicalDigest(artifactPayload, registryEntry.exclusion_set);
  const representation = registryEntry.representation ?? 'bare_hex';
  let finalDigest = digest;
  if (representation === 'prefixed') finalDigest = `sha256:${digest}`;
  return {
    type: registryEntry.name,
    digest_alg: 'SHA-256',
    digest: finalDigest,
  };
}

/** Verify a typed digest reference (§6.1).
 *  Returns the recomputed digest on success; throws TypedRefError on failure. */
export function verifyTypedRef(
  ref: TypedRefFields | Record<string, string>,
  artifactPayload: Record<string, unknown>,
  registryEntry: ArtifactTypeRegistryEntry,
): string {
  const typedRef = ref as TypedRefFields;
  // Type check: ref.type must match the registry entry name (§6).
  if (typedRef.type !== registryEntry.name) {
    throw new ContextMismatchError(
      typedRef.digest,
      `<type mismatch: ref.type='${typedRef.type}' vs registry name='${registryEntry.name}'>`,
      typedRef.type,
    );
  }
  // Representation check (§6.1).
  const repr = registryEntry.representation ?? 'bare_hex';
  _checkRepresentation(typedRef.digest, repr, registryEntry.name);
  // Recompute and compare (§6.1).
  const recomputed = canonicalDigest(artifactPayload, registryEntry.exclusion_set);
  let carriedBareHex = typedRef.digest;
  if (repr === 'prefixed') carriedBareHex = typedRef.digest.slice(7); // strip "sha256:"
  if (recomputed !== carriedBareHex) {
    throw new ContextMismatchError(typedRef.digest, recomputed, registryEntry.name);
  }
  return recomputed;
}
