import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { parsePolicyDocument } from '../src/policy/documents.js';
import { resolvePolicy } from '../src/policy/resolve.js';

test('hierarchical policy applies child override and preserves source order', () => {
  const org = parsePolicyDocument({
    schemaVersion: 1,
    id: 'org',
    version: '1',
    level: 'organization',
    enforcement: { failOn: ['critical'], warnOn: ['high'], requiredScanners: ['secrets'] }
  }, 'org.json');
  const repo = parsePolicyDocument({
    schemaVersion: 1,
    id: 'repo',
    version: '1',
    level: 'repository',
    enforcement: { failOn: ['high', 'critical'] }
  }, 'repo.json');
  const result = resolvePolicy(structuredClone(DEFAULT_CONFIG), [
    { path: 'org.json', document: org },
    { path: 'repo.json', document: repo }
  ]);
  assert.deepEqual(result.failOn, ['high', 'critical']);
  assert.deepEqual(result.requiredScanners, ['secrets']);
  assert.equal(result.sourceDocuments.length, 2);
  assert.match(result.fingerprint, /^[0-9a-f]{64}$/);
});

test('locked parent policy field cannot be weakened or changed by child', () => {
  const org = parsePolicyDocument({
    schemaVersion: 1,
    id: 'org',
    version: '1',
    level: 'organization',
    enforcement: { requiredScanners: ['secrets', 'dependencies'] },
    lock: ['requiredScanners']
  }, 'org.json');
  const repo = parsePolicyDocument({
    schemaVersion: 1,
    id: 'repo',
    version: '1',
    level: 'repository',
    enforcement: { requiredScanners: ['secrets'] }
  }, 'repo.json');
  assert.throws(() => resolvePolicy(structuredClone(DEFAULT_CONFIG), [
    { path: 'org.json', document: org },
    { path: 'repo.json', document: repo }
  ]), /cannot override locked field requiredScanners/);
});

test('policy document validation rejects unknown failure modes', () => {
  assert.throws(() => parsePolicyDocument({
    schemaVersion: 1,
    id: 'bad',
    version: '1',
    level: 'repository',
    enforcement: { scannerFailureModes: { dependencies: 'maybe' } }
  }, 'bad.json'), /must be fail, warn, or ignore/);
});
