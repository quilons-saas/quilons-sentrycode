import assert from 'node:assert/strict';
import test from 'node:test';
import { buildReleaseDecision } from '../src/policy/release.js';
import type { ScanReport } from '../src/core/types.js';

test('release decision emits release.gate evidence', () => {
  const report: ScanReport = {
    schemaVersion: '1.0.0',
    runId: 'run-1',
    startedAt: '2026-08-25T00:00:00.000Z',
    completedAt: '2026-08-25T00:00:01.000Z',
    repository: { root: '/repo', repository: 'repo', commitSha: 'abc', branch: 'main', isDirty: false },
    scanners: [],
    policy: {
      decision: 'PASS',
      findings: [],
      counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      waivedCount: 0,
      reasons: ['ok'],
      effectivePolicy: {
        sourceDocuments: [], failOn: ['high', 'critical'], warnOn: ['medium'],
        requiredScanners: [], scannerFailureModes: {}, lockedFields: [], fingerprint: 'fp'
      },
      audit: []
    },
    evidence: []
  };
  const result = buildReleaseDecision(report, new Date('2026-08-25T01:00:00Z'));
  assert.equal(result.decision.decision, 'PASS');
  assert.equal(result.evidence.type, 'release.gate');
  assert.equal(result.evidence.metadata.policyFingerprint, 'fp');
});
