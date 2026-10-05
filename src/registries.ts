// SPDX-License-Identifier: Apache-2.0
/**
 * Bundled registry values from spec/REGISTRY.md (Agent Action Capsule, §12).
 * tests/registry-parity.test.ts compares them with a pinned copy of that file
 * (tests/fixtures/REGISTRY.md); refresh it with scripts/refresh-registry.sh.
 * Unknown values remain informational. `citation_purpose` applies to
 * `references[].citation_purpose`, which this port does not verify yet: it is
 * exported for callers.
 */

export const REGISTRIES: Record<string, Set<string>> = {
  'verdict_class': new Set([
    'executed', 'blocked', 'hitl_dispatched', 'denied', 'timeout', 'errored',
    'engine_failure', 'deferred', 'needs_decision', 'expired', 'escalated', 'resolved',
    'epoch_boundary',
  ]),
  'disposition.decision': new Set(['accept', 'reject', 'needs_input', 'deferred']),
  'effect.type': new Set(['write_order', 'send_payment', 'inference_completion']),
  'irreversibility_class': new Set([
    'two_way', 'one_way_recoverable', 'one_way_consequential', 'one_way_terminal',
  ]),
  'effect_attestation': new Set(['gate_executed', 'runtime_claimed', 'host_served_observed']),
  'chain.relation': new Set(['follows', 'confirms', 'supersedes', 'epoch_opens', 'duplicates']),
  'citation_purpose': new Set([
    'acted_on', 'responds_to', 'ran_under', 'corroborates_source_time',
    'counterparty_half', 'counterparty_inclusion',
  ]),
};
