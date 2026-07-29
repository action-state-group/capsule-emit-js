// SPDX-License-Identifier: Apache-2.0
/** Bundled registry values from spec/REGISTRY.md (Agent Action Capsule, §12). */

export const REGISTRIES: Record<string, Set<string>> = {
  'verdict_class': new Set([
    'executed', 'blocked', 'hitl_dispatched', 'denied', 'timeout', 'errored',
    'engine_failure', 'deferred', 'needs_decision', 'expired', 'escalated', 'resolved',
  ]),
  'disposition.decision': new Set(['accept', 'reject', 'needs_input', 'deferred']),
  'effect.type': new Set(['write_order', 'send_payment']),
  'irreversibility_class': new Set([
    'two_way', 'one_way_recoverable', 'one_way_consequential', 'one_way_terminal',
  ]),
  'effect_attestation': new Set(['gate_executed', 'runtime_claimed']),
  'chain.relation': new Set(['confirms', 'supersedes']),
};
