import assert from 'node:assert/strict';
import test from 'node:test';
import { looksLikeHighEntropySecret, shannonEntropy } from '../src/scanners/secrets/entropy.js';

test('entropy distinguishes repetitive and random-looking values', () => {
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa') < 1);
  assert.ok(shannonEntropy('aZ93kLm2Pq7Tx4Vn8Rs1Yu5W') > 4);
});

test('high entropy detector requires minimum length and mixed character classes', () => {
  assert.equal(looksLikeHighEntropySecret('short123', 24), false);
  assert.equal(looksLikeHighEntropySecret('aZ93kLm2Pq7Tx4Vn8Rs1Yu5W', 24), true);
});

test('high entropy heuristic does not classify package registry URLs as candidates at scanner layer', async () => {
  const { mkdtemp, writeFile } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { SecretsScanner } = await import('../src/scanners/secrets/scanner.js');
  const { DEFAULT_CONFIG } = await import('../src/config/defaults.js');
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-url-'));
  await writeFile(join(root, 'package-lock.json'), 'https://registry.npmjs.org/good-lib/-/good-lib-1.2.3.tgz');
  const result = await new SecretsScanner().scan({ repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false }, config: structuredClone(DEFAULT_CONFIG), now: () => new Date('2026-08-25T00:00:00Z') });
  assert.equal(result.findings.some((item) => item.ruleId === 'high-entropy-token'), false);
});
