// SPDX-License-Identifier: Apache-2.0
/**
 * CPB derived identifier: CANONICAL-DIGEST(jcs-n, payload minus exclusion_set).
 * Reference: draft-mih-sokolov-scitt-payload-binding-00 §4.
 */
import { canonicalDigest } from './canonical.js';

export class CarriedIdMismatch extends Error {
  readonly carried: string;
  readonly recomputed: string;
  constructor(carried: string, recomputed: string) {
    super(
      `carried derived identifier ${carried} does not match recomputed ${recomputed} (§4)`,
    );
    this.name = 'CarriedIdMismatch';
    this.carried = carried;
    this.recomputed = recomputed;
  }
}

/** Compute the derived identifier of a payload (§4).
 *  id = CANONICAL-DIGEST(jcs-n, payload minus exclusion_set) */
export function deriveId(
  payload: Record<string, unknown>,
  exclusionSet?: Set<string> | string[] | readonly string[],
): string {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new TypeError('payload must be a JSON object');
  }
  return canonicalDigest(payload, exclusionSet);
}

/** Recompute and compare against the carried derived identifier (§4).
 *  Throws CarriedIdMismatch if recomputed !== carried value.
 *  Returns the recomputed identifier. */
export function verifyCarriedId(
  payload: Record<string, unknown>,
  carriedField: string,
  exclusionSet?: Set<string> | string[] | readonly string[],
): string {
  const recomputed = deriveId(payload, exclusionSet);
  const carried = payload[carriedField];
  if (carried !== undefined && carried !== null && carried !== recomputed) {
    throw new CarriedIdMismatch(String(carried), recomputed);
  }
  return recomputed;
}
