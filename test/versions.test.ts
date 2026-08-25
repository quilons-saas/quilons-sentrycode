import assert from 'node:assert/strict';
import test from 'node:test';
import { compareVersions, satisfiesSimpleRange } from '../src/dependencies/versions.js';

test('simple version comparison and ranges work for policy/advisory use', () => {
  assert.equal(compareVersions('2.0.0', '1.9.9'), 1);
  assert.equal(satisfiesSimpleRange('1.5.0', '>=1.0.0 <2.0.0'), true);
  assert.equal(satisfiesSimpleRange('2.1.0', '^2.0.0'), true);
  assert.equal(satisfiesSimpleRange('3.0.0', '^2.0.0'), false);
});
