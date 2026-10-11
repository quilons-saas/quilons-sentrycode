import test from 'node:test';
import assert from 'node:assert/strict';

import { boundedScannerLog } from '../src/execution/docker-executor.js';

test('scanner failure log becomes a single bounded line', () => {
  assert.equal(
    boundedScannerLog('first line\r\nsecond line\tthird'),
    'first line second line third'
  );
});

test('scanner failure log preserves empty output as empty diagnostic', () => {
  assert.equal(boundedScannerLog(' \r\n\t '), '');
});

test('scanner failure log is capped deterministically', () => {
  const value = boundedScannerLog('x'.repeat(2000), 64);
  assert.equal(value.length, 64);
  assert.equal(value.endsWith('...'), true);
});