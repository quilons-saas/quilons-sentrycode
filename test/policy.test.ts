import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { evaluatePolicy } from '../src/policy/evaluate.js';
import type { Finding, ScannerResult } from '../src/core/types.js';

const finding: Finding = {
  schemaVersion: '1.0.0',
  id: 'finding_1',
  type: 'secret',
  scanner: 'secrets',
  ruleId: 'generic-secret-assignment',
  title: 'Secret',
  description: 'Secret',
  severity: 'high',
  fingerprint: 'fp_1',
  location: { path: 'src/a.ts', line: 1 },
  detectedAt: '2026-08-25T00:00:00.000Z'
};
const scanner: ScannerResult = { scanner: 'secrets', findings: [finding], evidence: [], durationMs: 1 };
const dependencies: ScannerResult = { scanner: 'dependencies', findings: [], evidence: [], durationMs: 1 };
const sast: ScannerResult = { scanner: 'sast', findings: [], evidence: [], durationMs: 1 };
const gitAssurance: ScannerResult = { scanner: 'git-assurance', findings: [], evidence: [], durationMs: 1 };
const requiredScanners = [scanner, dependencies, sast, gitAssurance];

test('high finding fails default policy', () => {
  const result = evaluatePolicy(structuredClone(DEFAULT_CONFIG), requiredScanners, [], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'FAIL');
});

test('active waiver suppresses policy failure but retains finding', () => {
  const result = evaluatePolicy(structuredClone(DEFAULT_CONFIG), requiredScanners, [{ id: 'w1', fingerprint: 'fp_1', reason: 'approved', expiresAt: '2027-01-01T00:00:00Z' }], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'PASS');
  assert.equal(result.waivedCount, 1);
  assert.equal(result.findings[0]?.waived, true);
});

test('expired waiver does not suppress policy failure', () => {
  const result = evaluatePolicy(structuredClone(DEFAULT_CONFIG), requiredScanners, [{ id: 'w1', fingerprint: 'fp_1', reason: 'expired', expiresAt: '2026-01-01T00:00:00Z' }], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'FAIL');
});
