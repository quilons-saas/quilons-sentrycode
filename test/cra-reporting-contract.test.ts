import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCraFindingReport, CRA_REPORTING_CONTRACT_VERSION } from '../src/compliance/cra-reporting.js';
import { COMPLIANCE_API_VERSION } from '../src/compliance/contracts.js';
import type { ScanReport } from '../src/core/types.js';

function fixture(): ScanReport {
  return {
    schemaVersion: '1.0.0',
    runId: 'run-123',
    startedAt: '2026-08-31T01:00:00.000Z',
    completedAt: '2026-08-31T01:00:05.000Z',
    repository: { root: '/repo', repository: 'payments', commitSha: 'abc123', branch: 'main', isDirty: false },
    scanners: [],
    policy: {
      decision: 'FAIL',
      findings: [{
        waived: false,
        finding: {
          schemaVersion: '1.0.0', id: 'finding-1', type: 'vulnerability', scanner: 'dependencies', ruleId: 'vuln.CVE-1',
          title: 'Critical vulnerability', description: 'Dependency x contains CVE-1.', severity: 'critical', fingerprint: 'fp-1',
          detectedAt: '2026-08-31T01:00:03.000Z'
        }
      }],
      counts: { info: 0, low: 0, medium: 0, high: 0, critical: 1 }, waivedCount: 0, reasons: [], audit: []
    },
    evidence: [{
      schemaVersion: '1.0.0', id: 'evidence-1', type: 'vuln.scan', scanner: 'dependencies', repository: 'payments', commitSha: 'abc123',
      branch: 'main', generatedAt: '2026-08-31T01:00:03.000Z', findingIds: ['finding-1'], metadata: { findingCount: 1 }
    }],
    execution: { mode: 'full', changedFiles: [], ci: { provider: 'gerrit', detected: true, pullRequest: true, buildId: 'b-7', changeNumber: '42', patchsetNumber: '3', revision: 'abc123' } }
  };
}

test('CRA reporting contract reuses governed identity and evidence references without regulatory verdicts', () => {
  const report = fixture();
  const built = buildCraFindingReport({
    identity: { tenant: 'acme', project: 'payments-platform' },
    report,
    appliedFinding: report.policy.findings[0]!,
    productVersion: '0.1.0',
    reportedAt: '2026-08-31T01:00:06.000Z'
  });

  assert.equal(built.contractVersion, CRA_REPORTING_CONTRACT_VERSION);
  assert.equal(built.tenant, 'acme');
  assert.equal(built.project, 'payments-platform');
  assert.equal(built.repository, 'payments');
  assert.equal(built.finding.severity, 'critical');
  assert.equal(built.finding.status, 'active');
  assert.equal(built.evidenceReference.apiVersion, COMPLIANCE_API_VERSION);
  assert.deepEqual(built.evidenceReference.evidenceIds, ['evidence-1']);
  assert.equal(built.evidenceReference.resourcePath, '/v1/runs/run-123/evidence');
  assert.equal(built.sourceRevision.changeNumber, '42');
  assert.equal(built.sourceRevision.patchsetNumber, '3');
  assert.equal(built.timestamps.detectedAt, '2026-08-31T01:00:03.000Z');
  assert.equal('craViolation' in built, false);
  assert.equal('complianceStatus' in built, false);
});

test('CRA report identity is stable for the same governed finding', () => {
  const report = fixture();
  const one = buildCraFindingReport({ identity:{tenant:'t',project:'p'}, report, appliedFinding:report.policy.findings[0]!, productVersion:'0.1.0', reportedAt:'2026-08-31T02:00:00Z' });
  const two = buildCraFindingReport({ identity:{tenant:'t',project:'p'}, report, appliedFinding:report.policy.findings[0]!, productVersion:'0.1.0', reportedAt:'2026-08-31T03:00:00Z' });
  assert.equal(one.reportId, two.reportId);
});

test('CRA report creation requires authoritative evidence linked to the finding', () => {
  const report = fixture();
  report.evidence = [];
  assert.throws(() => buildCraFindingReport({ identity:{tenant:'t',project:'p'}, report, appliedFinding:report.policy.findings[0]!, productVersion:'0.1.0' }), /No authoritative evidence/);
});
