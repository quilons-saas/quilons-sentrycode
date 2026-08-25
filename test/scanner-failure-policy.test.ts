import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { evaluatePolicy } from '../src/policy/evaluate.js';
import type { ScannerResult } from '../src/core/types.js';

const dependencyFailure: ScannerResult = {
  scanner: 'dependencies',
  findings: [],
  evidence: [],
  durationMs: 1,
  status: 'failed',
  error: 'database unavailable'
};
const secrets: ScannerResult = { scanner: 'secrets', findings: [], evidence: [], durationMs: 1, status: 'success' };

test('required scanner failure fails closed by default', () => {
  const result = evaluatePolicy(structuredClone(DEFAULT_CONFIG), [secrets, dependencyFailure], [], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'FAIL');
  assert.match(result.reasons.join(' '), /failed closed/);
});

test('scanner failure can be configured to warn', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.policy.scannerFailureModes.dependencies = 'warn';
  const result = evaluatePolicy(config, [secrets, dependencyFailure], [], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'WARN');
});


test('required scanner skipped by configuration is treated as not run', () => {
  const skipped: ScannerResult = {
    scanner: 'dependencies',
    findings: [],
    evidence: [],
    durationMs: 0,
    status: 'skipped',
    error: 'scanner disabled by configuration'
  };
  const result = evaluatePolicy(structuredClone(DEFAULT_CONFIG), [secrets, skipped], [], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'FAIL');
  assert.match(result.reasons.join(' '), /did not run/);
});
