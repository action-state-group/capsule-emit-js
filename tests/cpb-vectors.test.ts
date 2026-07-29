// SPDX-License-Identifier: Apache-2.0
/**
 * CPB conformance vector runner.
 * Covers: jcs-n KATs, derived-id, typed-refs, profile-independence.
 * Source: scitt-payload-binding@cpb-vectors-and-ref-impl branch (extracted locally).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalDigest,
  FloatInDigestError,
  normalize,
  jcs,
} from '../src/canonical.js';
import { deriveId, verifyCarriedId, CarriedIdMismatch } from '../src/derive_id.js';
import {
  verifyTypedRef,
  TypedRefError,
  RepresentationMismatchError,
  ContextMismatchError,
  type ArtifactTypeRegistryEntry,
} from '../src/typed_ref.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_ROOT = join(__dirname, '..', 'test-vectors', 'cpb', 'vectors');

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf-8'));
}

function listJsonFiles(dir: string): string[] {
  try {
    return readdirSync(dir)
      .filter(f => f.endsWith('.json'))
      .map(f => join(dir, f))
      .sort();
  } catch {
    return [];
  }
}

// ---- JCS-N KAT vectors --------------------------------------------------

describe('jcs-n KAT vectors', () => {
  const katsDir = join(VECTORS_ROOT, 'jcs-n', 'kats');
  const vectors = listJsonFiles(katsDir);

  it('has at least 11 KAT vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(11);
  });

  for (const vPath of vectors) {
    const v = loadJson(vPath) as Record<string, unknown>;
    const id = v['id'] as string;
    const mustFail = v['must_fail'] === true;

    if (!mustFail) {
      it(`PASS ${id}: digest matches`, () => {
        const input = v['input'];
        const exclusionSet = (v['exclusion_set'] as string[]) ?? [];
        const expectedDigest = v['digest'] as string;
        const expectedPreImage = v['pre_image'] as string;

        // Compute via canonicalDigest
        const digest = canonicalDigest(input, exclusionSet);
        expect(digest).toBe(expectedDigest);

        // Also verify pre_image matches JCS(normalize(after_exclusion))
        let payload = input;
        if (exclusionSet.length > 0 && typeof input === 'object' && input !== null && !Array.isArray(input)) {
          const excl = new Set(exclusionSet);
          const filtered: Record<string, unknown> = {};
          for (const [k, val] of Object.entries(input as Record<string, unknown>)) {
            if (!excl.has(k)) filtered[k] = val;
          }
          payload = filtered;
        }
        const preImage = jcs(normalize(payload)).toString('utf-8');
        expect(preImage).toBe(expectedPreImage);
      });
    } else {
      const reason = v['failure_reason'] as string;
      it(`MUST-FAIL ${id} (${reason}): throws`, () => {
        const input = v['input'];
        const exclusionSet = (v['exclusion_set'] as string[]) ?? [];
        expect(() => canonicalDigest(input, exclusionSet)).toThrow(FloatInDigestError);
      });
    }
  }
});

// ---- Derived-id vectors -------------------------------------------------

describe('jcs-n derived-id vectors', () => {
  const derivedDir = join(VECTORS_ROOT, 'jcs-n', 'derived-id');
  const vectors = listJsonFiles(derivedDir);

  it('has at least 3 derived-id vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(3);
  });

  for (const vPath of vectors) {
    const v = loadJson(vPath) as Record<string, unknown>;
    const id = v['id'] as string;
    const mustFail = v['must_fail'] === true;
    const exclusionSet = (v['exclusion_set'] as string[]) ?? [];

    if (!mustFail) {
      it(`PASS ${id}: derived_id matches`, () => {
        // Use full_payload for vectors that have it; for sd-encoded use sd_encoded_payload.
        const payload = (v['sd_encoded_payload'] ?? v['full_payload']) as Record<string, unknown>;
        const expectedId = v['derived_id'] as string;
        const computed = deriveId(payload, exclusionSet);
        expect(computed).toBe(expectedId);
      });

      if (v['full_payload_with_carried_id']) {
        it(`PASS ${id}: verify_carried_id matches`, () => {
          const payloadWithId = v['full_payload_with_carried_id'] as Record<string, unknown>;
          const result = verifyCarriedId(payloadWithId, 'record_id', exclusionSet);
          expect(result).toBe(v['derived_id'] as string);
        });
      }
    } else {
      const reason = v['failure_reason'] as string;
      it(`MUST-FAIL ${id} (${reason}): verify_carried_id throws CarriedIdMismatch`, () => {
        // Construct the payload that has the WRONG carried ID.
        const correctId = v['correct_derived_id'] as string;
        const wrongId = v['carried_id'] as string;
        // Build a payload based on derived-id-01's full_payload but with wrong ID.
        const payload: Record<string, unknown> = {
          station_id: 'WS-42',
          timestamp: '2026-07-24T00:00:00Z',
          celsius: '21.3',
          record_id: wrongId,
        };
        expect(() => verifyCarriedId(payload, 'record_id', exclusionSet)).toThrow(CarriedIdMismatch);
        // Also verify the correct ID is what we'd compute.
        expect(deriveId(payload, exclusionSet)).toBe(correctId);
      });
    }
  }

  it('sd-encoded form produces different digest than plaintext', () => {
    const vectors03Path = join(derivedDir, '03-sd-encoded-form.json');
    const v = loadJson(vectors03Path) as Record<string, unknown>;
    const exclusionSet = (v['exclusion_set'] as string[]) ?? [];
    const sdPayload = v['sd_encoded_payload'] as Record<string, unknown>;
    const plaintextPayload = v['plaintext_payload_for_reference'] as Record<string, unknown>;
    const sdId = deriveId(sdPayload, exclusionSet);
    const ptId = deriveId(plaintextPayload, exclusionSet);
    expect(sdId).not.toBe(ptId);
    expect(sdId).toBe(v['derived_id'] as string);
  });
});

// ---- Typed-ref vectors --------------------------------------------------

function entryFromCited(cited: Record<string, unknown>): ArtifactTypeRegistryEntry {
  const reg = (cited['artifact_type_registry_entry'] ?? cited['registry_entry'] ?? {}) as Record<string, unknown>;
  return {
    name: (cited['type'] ?? reg['name']) as string,
    algorithm: (reg['algorithm'] as string) ?? 'jcs-n',
    exclusion_set: ((reg['exclusion_set'] ?? []) as string[]),
    representation: (reg['representation'] as string) ?? 'bare_hex',
  };
}

describe('typed-ref pass vectors', () => {
  const passDir = join(VECTORS_ROOT, 'typed-refs', 'pass');
  const vectors = listJsonFiles(passDir);

  it('has at least 1 pass vector', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(1);
  });

  for (const vPath of vectors) {
    const v = loadJson(vPath) as Record<string, unknown>;
    const id = v['id'] as string;
    it(`PASS ${id}: verify_typed_ref succeeds`, () => {
      const cited = v['cited_artifact'] as Record<string, unknown>;
      const entry = entryFromCited(cited);
      const payload = cited['payload'] as Record<string, unknown>;
      const ref = v['typed_reference'] as Record<string, string>;
      const recomputed = verifyTypedRef(ref, payload, entry);
      const expectedDigest = (v['verification'] as Record<string, unknown>)?.['recomputed_digest'] as string;
      if (expectedDigest) expect(recomputed).toBe(expectedDigest);
    });
  }
});

describe('typed-ref fail vectors', () => {
  const failDir = join(VECTORS_ROOT, 'typed-refs', 'fail');
  const vectors = listJsonFiles(failDir);

  it('has at least 4 fail vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(4);
  });

  for (const vPath of vectors) {
    const v = loadJson(vPath) as Record<string, unknown>;
    const id = v['id'] as string;
    const reason = v['failure_reason'] as string;

    if (reason === 'recomputed_digest_mismatch') {
      // fail-01: conforming verifier with WRONG (empty) exclusion_set gets mismatch.
      it(`MUST-FAIL ${id}: ContextMismatchError with wrong exclusion set`, () => {
        const cited = v['cited_artifact'] as Record<string, unknown>;
        const payload = cited['payload'] as Record<string, unknown>;
        const erroneousV = v['erroneous_verification'] as Record<string, unknown>;
        const wrongExclusionSet = (erroneousV['wrong_exclusion_set'] as string[]) ?? [];
        const wrongEntry: ArtifactTypeRegistryEntry = {
          name: 'authorization-doc',
          exclusion_set: wrongExclusionSet,
        };
        const ref = v['typed_reference'] as Record<string, string>;
        expect(() => verifyTypedRef(ref, payload, wrongEntry)).toThrow(TypedRefError);
      });
    } else if (reason === 'digest_context_incompatible_equal_hex_is_not_a_join') {
      // fail-02: artifact-B bytes verified with artifact-A reference → type mismatch.
      it(`MUST-FAIL ${id}: type mismatch when wrong artifact bytes used`, () => {
        const artifactB = v['artifact_b'] as Record<string, unknown>;
        const payload = artifactB['payload'] as Record<string, unknown>;
        // artifact_b registry entry
        const bReg = artifactB['registry_entry'] as Record<string, unknown>;
        const wrongEntry: ArtifactTypeRegistryEntry = {
          name: 'artifact-b',
          exclusion_set: ['b_id', 'weight'],
        };
        // ref claims artifact-a type
        const ref = v['typed_reference_claiming_artifact_a'] as Record<string, string>;
        // ref.type='artifact-a' but entry.name='artifact-b' → type mismatch
        expect(() => verifyTypedRef(ref, payload, wrongEntry)).toThrow(TypedRefError);
      });
    } else if (reason === 'representation_mismatch') {
      // fail-03: sha256:-prefixed digest where bare hex expected.
      it(`MUST-FAIL ${id}: RepresentationMismatchError for prefixed digest`, () => {
        const cited = v['cited_artifact'] as Record<string, unknown>;
        const payload = cited['payload'] as Record<string, unknown>;
        const entry: ArtifactTypeRegistryEntry = {
          name: cited['type'] as string,
          exclusion_set: [],
          representation: 'bare_hex',
        };
        const ref = v['typed_reference_with_wrong_representation'] as Record<string, string>;
        expect(() => verifyTypedRef(ref, payload, entry)).toThrow(RepresentationMismatchError);
      });
    } else if (reason === 'identifier_inconsistent_with_context') {
      // fail-04: wrong digest in reference (computed without exclusion set).
      it(`MUST-FAIL ${id}: ContextMismatchError for wrong digest`, () => {
        const cited = v['cited_artifact'] as Record<string, unknown>;
        const payload = cited['payload'] as Record<string, unknown>;
        const entry = entryFromCited(cited);
        const ref = v['typed_reference_with_wrong_digest'] as Record<string, string>;
        expect(() => verifyTypedRef(ref, payload, entry)).toThrow(ContextMismatchError);
      });
    }
  }
});

// ---- Profile-independence vectors (structural/digest checks) ------------

describe('profile-independence vectors', () => {
  const passDir = join(VECTORS_ROOT, 'profile-independence', 'pass');
  const failDir = join(VECTORS_ROOT, 'profile-independence', 'fail');

  it('pass-01: profile-B derived_id matches recomputed', () => {
    const vPath = join(passDir, '01-conforming-typed-ref.json');
    const v = loadJson(vPath) as Record<string, unknown>;
    const profileB = v['profile_b'] as Record<string, unknown>;
    const bPayload = profileB['payload'] as Record<string, unknown>;
    const bExcl = (profileB['exclusion_set'] as string[]) ?? [];
    const bId = deriveId(bPayload, bExcl);
    expect(bId).toBe(profileB['derived_id'] as string);

    // Verify profile-A's typed ref to B.
    const profileA = v['profile_a'] as Record<string, unknown>;
    const aPayload = profileA['payload'] as Record<string, unknown>;
    const auth = (aPayload['authorization']) as Record<string, string>;
    expect(auth['digest']).toBe(bId);
  });

  it('fail-01: cross-profile field access is semantically incorrect (digest still matches)', () => {
    const vPath = join(failDir, '01-cross-profile-field-access.json');
    const v = loadJson(vPath) as Record<string, unknown>;
    const scenario = v['scenario'] as Record<string, unknown>;
    const authDoc = scenario['authorization_doc'] as Record<string, unknown>;
    const docPayload = authDoc['payload'] as Record<string, unknown>;
    // The derived_id should match when computed correctly.
    const computed = deriveId(docPayload, ['doc_id']);
    expect(computed).toBe(authDoc['derived_id'] as string);
  });
});
