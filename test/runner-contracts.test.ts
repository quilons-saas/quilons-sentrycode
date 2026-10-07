import test from 'node:test';
import assert from 'node:assert/strict';
import { constantTimeTokenMatch, immutableImageDigest, validateProfileId, validateRunId } from '../src/execution/contracts.js';

test('runner accepts only digest-pinned image references', () => {
  const digest = 'a'.repeat(64);
  assert.equal(immutableImageDigest(`ghcr.io/example/tool@sha256:${digest}`), digest);
  assert.equal(immutableImageDigest('ghcr.io/example/tool:latest'), undefined);
  assert.equal(immutableImageDigest('ghcr.io/example/tool@sha256:short'), undefined);
});

test('runner identifiers reject path and shell metacharacters', () => {
  assert.equal(validateRunId('run-123:abc'), 'run-123:abc');
  assert.equal(validateProfileId('syft-grype'), 'syft-grype');
  assert.throws(() => validateRunId('../escape'), /Invalid runner runId/);
  assert.throws(() => validateProfileId('bad/profile'), /Invalid runner profileId/);
});

test('runner bearer token comparison is exact', () => {
  assert.equal(constantTimeTokenMatch('secret-value', 'secret-value'), true);
  assert.equal(constantTimeTokenMatch('secret-value-x', 'secret-value'), false);
  assert.equal(constantTimeTokenMatch('secret-valuE', 'secret-value'), false);
});
