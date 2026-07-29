// SPDX-License-Identifier: Apache-2.0
/**
 * AAC conformance vector runner.
 * Source: agent-action-capsule/test-vectors/ (copied locally).
 * Runs all 32 vectors through verify() / verify_store() and asserts expected.json.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verify, verifyStore, type VerificationResult, type Finding } from '../src/verify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_ROOT = join(__dirname, '..', 'test-vectors', 'aac');

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf-8'));
}

type ExpectedFinding = { check: number | null; severity: string; code: string };

function findingsProjection(result: VerificationResult): ExpectedFinding[] {
  return result.findings.map(f => ({ check: f.check, severity: f.severity, code: f.code }));
}

function expectedFindings(exp: Record<string, unknown>): ExpectedFinding[] {
  return ((exp['findings'] as ExpectedFinding[]) ?? []).map(f => ({
    check: f.check,
    severity: f.severity,
    code: f.code,
  }));
}

function assertSingle(result: VerificationResult, exp: Record<string, unknown>): void {
  expect(result.ok).toBe(exp['ok']);
  expect(result.assurance).toEqual(exp['derived']);
  expect(result.capsule_id).toBe(exp['capsule_id_recomputed'] ?? null);
  expect(findingsProjection(result)).toEqual(expectedFindings(exp));
}

// Load the manifest to get vector names in order.
const manifest = loadJson(join(VECTORS_ROOT, 'vectors.json')) as {
  count: number;
  cases: Array<{ name: string; kind: string }>;
};
const cases = manifest.cases;

describe('AAC conformance vectors', () => {
  it(`manifest declares ${manifest.count} cases`, () => {
    // Verify all named directories exist.
    const dirs = readdirSync(VECTORS_ROOT).filter(f =>
      statSync(join(VECTORS_ROOT, f)).isDirectory(),
    );
    const dirSet = new Set(dirs);
    for (const c of cases) {
      expect(dirSet.has(c.name)).toBe(true);
    }
    expect(cases.length).toBe(manifest.count);
  });

  for (const { name, kind } of cases) {
    it(`${name} (${kind})`, () => {
      const caseDir = join(VECTORS_ROOT, name);
      const inp = loadJson(join(caseDir, 'input.json')) as Record<string, unknown>;
      const exp = loadJson(join(caseDir, 'expected.json')) as Record<string, unknown>;

      if ('ledger' in inp) {
        const ledger = inp['ledger'] as unknown[];
        const results = verifyStore(ledger);
        const expectedResults = exp['results'] as Record<string, unknown>[];
        expect(results.length).toBe(expectedResults.length);
        for (let i = 0; i < results.length; i++) {
          assertSingle(results[i], expectedResults[i]);
        }
      } else {
        assertSingle(verify(inp), exp);
      }
    });
  }
});
