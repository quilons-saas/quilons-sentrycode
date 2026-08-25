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

test('approval-required waiver without approval is rejected and audited', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.waivers.requireApproval = true;
  const result = evaluatePolicy(config, requiredScanners, [{
    id: 'w1', fingerprint: 'fp_1', reason: 'temporary', expiresAt: '2026-09-01T00:00:00Z'
  }], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'FAIL');
  assert.equal(result.waivedCount, 0);
  assert.equal(result.audit.some((entry) => entry.event === 'waiver.rejected' && entry.waiverId === 'w1'), true);
});

test('approved ticketed time-bounded waiver applies under governed policy', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.waivers.requireApproval = true;
  config.waivers.requireTicket = true;
  config.waivers.maxDurationDays = 30;
  const result = evaluatePolicy(config, requiredScanners, [{
    id: 'w1',
    fingerprint: 'fp_1',
    reason: 'temporary',
    ticket: 'SEC-1',
    author: 'dev',
    approver: 'security',
    createdAt: '2026-08-20T00:00:00Z',
    approvedAt: '2026-08-20T01:00:00Z',
    expiresAt: '2026-09-01T00:00:00Z'
  }], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'PASS');
  assert.equal(result.waivedCount, 1);
  assert.equal(result.audit.some((entry) => entry.event === 'waiver.applied'), true);
});

test('waiver exceeding maximum duration is rejected', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.waivers.maxDurationDays = 10;
  const result = evaluatePolicy(config, requiredScanners, [{
    id: 'w1',
    fingerprint: 'fp_1',
    reason: 'too long',
    createdAt: '2026-08-01T00:00:00Z',
    expiresAt: '2026-09-01T00:00:00Z'
  }], new Date('2026-08-25T00:00:00Z'));
  assert.equal(result.decision, 'FAIL');
  assert.match(result.audit.find((entry) => entry.event === 'waiver.rejected')?.reason ?? '', /duration exceeds/);
});
