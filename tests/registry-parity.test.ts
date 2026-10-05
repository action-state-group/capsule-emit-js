// SPDX-License-Identifier: Apache-2.0
/**
 * The bundled registries mirror spec/REGISTRY.md. Nothing in the spec is
 * machine-readable, so this test reads a PINNED copy of it
 * (tests/fixtures/REGISTRY.md, with its source commit and SHA-256 in
 * REGISTRY.source.json) and fails when a mirrored set diverges from it.
 * To follow a newer spec: scripts/refresh-registry.sh <commit>, then update
 * src/registries.ts and src/contracts.ts until this passes.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DOMAIN_VALUES, PROVENANCE_VALUES, REGISTRIES } from '../src/index.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const registryMd = readFileSync(join(fixtures, 'REGISTRY.md'), 'utf8');
const source = JSON.parse(readFileSync(join(fixtures, 'REGISTRY.source.json'), 'utf8')) as {
  commit: string;
  sha256: string;
};

/**
 * Seeded values of one "## N. `name`" section, read as the reference ports
 * read it: table rows, ordered-list items and "Initial contents" lines only,
 * never prose backticks.
 */
function seededValues(name: string): Set<string> {
  const lines = registryMd.split('\n');
  const start = lines.findIndex((line) =>
    new RegExp(`^## \\d+\\. \`${name.replace('.', '\\.')}\``).test(line),
  );
  if (start < 0) throw new Error(`registry section ${name} not found in the pinned REGISTRY.md`);
  const values = new Set<string>();
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsWith('## ')) break;
    const stripped = line.trim();
    const row = /^\|\s*`([^`]+)`\s*\|/.exec(stripped);
    if (row) values.add(row[1]!);
    const item = /^\d+\.\s+`([^`]+)`\s*$/.exec(stripped);
    if (item) values.add(item[1]!);
    if (stripped.includes('Initial contents')) {
      for (let j = i; j < lines.length && lines[j]!.trim() !== ''; j++) {
        const text = j === i ? lines[j]!.slice(lines[j]!.indexOf('Initial contents')) : lines[j]!;
        for (const match of text.matchAll(/`([^`]+)`/g)) values.add(match[1]!);
      }
    }
  }
  return values;
}

describe(`registries mirror spec/REGISTRY.md at agent-action-capsule ${source.commit.slice(0, 7)}`, () => {
  it('the pinned copy is the one its source file names', () => {
    expect(createHash('sha256').update(registryMd).digest('hex')).toBe(source.sha256);
  });

  it.each(Object.keys(REGISTRIES))('registry %s', (name) => {
    expect([...REGISTRIES[name]!].sort()).toEqual([...seededValues(name)].sort());
  });

  it('domain', () => {
    expect([...DOMAIN_VALUES].sort()).toEqual([...seededValues('domain')].sort());
  });

  it('provenance', () => {
    expect([...PROVENANCE_VALUES].sort()).toEqual([...seededValues('provenance')].sort());
  });

  it('every value registry the spec seeds that this port checks is mirrored', () => {
    for (const name of ['verdict_class', 'disposition.decision', 'effect.type', 'irreversibility_class',
      'effect_attestation', 'chain.relation', 'citation_purpose']) {
      expect(Object.keys(REGISTRIES)).toContain(name);
    }
  });
});
