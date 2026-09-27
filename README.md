# capsule-emit-js

> **Deprecated.** This package implements draft -02 of the Agent Action Capsule profile
> (format 2, `jcs-n`) and is no longer maintained. Use
> [capsule-emit-ts](https://github.com/action-state-group/capsule-emit-ts)
> (`@action-state-group/capsule-emit`), which implements format 4 and the current
> `draft-mih-scitt-agent-action-capsule-05` wire. Existing releases stay published.

Spec-pure JavaScript/TypeScript port of the
[Agent Action Capsule](https://github.com/action-state-group/agent-action-capsule)
canonicalization, emission, and verification core.

Implements:

- **Algorithm jcs-n** — absent-field normalization + RFC 8785 JCS + SHA-256
  (draft-mih-sokolov-scitt-payload-binding-00 §3.1)
- **Derived identifier** — `derive_id`, `verify_carried_id`
  (draft-mih-sokolov-scitt-payload-binding-00 §4)
- **Typed digest references** — `make_typed_ref`, `verify_typed_ref`
  (draft-mih-sokolov-scitt-payload-binding-00 §6)
- **emit()** — sealed Agent Action Capsule builder with self-attestation
  (draft-mih-scitt-agent-action-capsule-02 §5)
- **verify() + verify_store()** — Class 1 payload verifier, all §6 checks
  (draft-mih-scitt-agent-action-capsule-02 §6)

**The vector suite is the acceptance gate.** The 60-vector suite (27 CPB
conformance vectors + 33 AAC assertions against 32 frozen capsule cases)
runs on every push and pull request. Passing the same vectors as the Python
and Go reference implementations establishes byte-level compatibility.

---

## Requirements

Node.js ≥ 18. No production dependencies — uses only `node:crypto`.

## Install

```sh
npm install agent-action-capsule   # name TBD — see below
```

> **Note:** The npm package name has not been finalized. The library is
> published at the operator's discretion. Do not rely on the current
> `package.json` name field until a stable release is tagged.

## Usage

### Emit a capsule

```typescript
import { emit } from 'agent-action-capsule';

const capsule = emit({
  action_type: 'decide',
  operator: 'acme-corp',
  developer: 'purchase-agent@v1',
  tool_name: 'submit_purchase_order',
  disposition: {
    decision: 'accept',
    approver: 'policy',
    verdict_class: 'executed',
  },
  effect: { status: 'confirmed', type: 'write_order', response_digest: '<64-hex>' },
});
console.log(capsule.capsule_id); // 64-char lowercase hex
```

### Verify a capsule

```typescript
import { verify } from 'agent-action-capsule';

const result = verify(capsuleDictFromStorage);
console.log(result.ok);        // boolean
console.log(result.findings);  // [{code, detail, severity, check}]
console.log(result.capsule_id); // recomputed capsule_id (null if uncomputable)
```

### JCS-N canonicalization (CPB)

```typescript
import { canonicalDigest, deriveId, normalize, jcs } from 'agent-action-capsule';

// Canonical digest with exclusion set
const digest = canonicalDigest(payload, ['record_id']);

// Derive and verify a carried identifier
import { deriveId, verifyCarriedId } from 'agent-action-capsule';
const id = deriveId(payload, ['record_id']);
verifyCarriedId(payloadWithCarriedId, 'record_id', ['record_id']); // throws on mismatch
```

### Typed digest references

```typescript
import { makeTypedRef, verifyTypedRef } from 'agent-action-capsule';

const ref = makeTypedRef(artifactPayload, {
  name: 'authorization-doc',
  exclusion_set: ['doc_id'],
});
// ref = { type: 'authorization-doc', digest_alg: 'SHA-256', digest: '...' }

verifyTypedRef(ref, artifactPayload, { name: 'authorization-doc', exclusion_set: ['doc_id'] });
```

## Run the vector suite

```sh
npm install
npm test
```

Expected output: **60 passed** (vitest).

The vectors are vendored in `test-vectors/`:
- `test-vectors/cpb/` — CPB conformance vectors from
  `scitt-payload-binding@cpb-vectors-and-ref-impl`
- `test-vectors/aac/` — AAC conformance vectors from
  `agent-action-capsule/test-vectors/`

## Phase 1 scope and honest limitations

**In scope (phase 1):**

- Algorithm jcs-n: normalize, jcs, json_digest, canonical_digest,
  compute_capsule_id
- CPB: derive_id, verify_carried_id, make_typed_ref, verify_typed_ref
- AAC emit(): capsule builder, seal, field assembly, effect-mode derivation
- AAC Class 1 verify() + verify_store(): all eight structural/semantic checks
  in §6, plus domain/provenance registry checks

**Not in scope (phase 1):**

- **Anchor client** — no HTTP submission to a SCITT Transparency Service;
  the `anchored` assurance mode is not claimed
- **Framework adapters** — no MCP, LangChain.js, or Vercel AI SDK wrappers
  (planned phase 2)
- **Substrate verification** — COSE_Sign1 signature and Receipt verification
  are out of scope for the Class 1 payload verifier (same scope as the
  Python/Go reference implementations)
- **Class 2 (manifest-aware) verification** — out of scope per spec
- **Selective disclosure mechanics** — the SD-encoded-form hook in
  `derive_id` is included; the full SD presentation layer is not
- **npm publication** — not published; no release yet

## Specs

- **CPB:** [draft-mih-sokolov-scitt-payload-binding-00](https://github.com/action-state-group/scitt-payload-binding)
- **AAC:** [draft-mih-scitt-agent-action-capsule-02](https://github.com/action-state-group/agent-action-capsule)

## License

Apache 2.0 — see [LICENSE](LICENSE).

All contributions require a DCO `Signed-off-by` line (`git commit -s`).
