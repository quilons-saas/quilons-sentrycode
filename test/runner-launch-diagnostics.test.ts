import test from 'node:test';
import assert from 'node:assert/strict';

import { boundedRunnerDiagnostic } from '../src/execution/runner-server.js';

test('runner launch diagnostic preserves useful cause as a bounded single line', () => {
  const diagnostic = boundedRunnerDiagnostic(new Error('docker create failed\r\npermission denied\twhile mounting'));
  assert.equal(diagnostic, 'docker create failed permission denied while mounting');
});

test('runner launch diagnostic bounds untrusted runtime error text', () => {
  const diagnostic = boundedRunnerDiagnostic(new Error('x'.repeat(2000)), 64);
  assert.equal(diagnostic.length, 64);
  assert.equal(diagnostic.endsWith('...'), true);
});

test('runner launch diagnostic handles non-Error and empty causes deterministically', () => {
  assert.equal(boundedRunnerDiagnostic('runtime unavailable'), 'runtime unavailable');
  assert.equal(boundedRunnerDiagnostic('   '), 'unknown runner launch failure');
});