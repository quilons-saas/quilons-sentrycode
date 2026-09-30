import test from 'node:test';
import assert from 'node:assert/strict';
import { buildTechnicalFindingEnvelope } from '../src/consumers/envelope.js';
import type { ScanReport } from '../src/core/types.js';

function fixture(): ScanReport {
  return {
    schemaVersion: '1.0.0', runId: 'run-1', startedAt: '2026-09-30T08:00:00.000Z', completedAt: '2026-09-30T08:01:00.000Z',
    repository: { root: '/repo', repository: 'product', commitSha: 'abc123', branch: 'main', isDirty: false },
    scanners: [],
    policy: {
      decision: 'FAIL',
      findings: [{ finding: { schemaVersion:'1.0.0', id:'finding-1', type:'vulnerability', scanner:'dependencies', ruleId:'CVE-X', title:'Issue', description:'Technical issue', severity:'high', fingerprint:'fp', detectedAt:'2026-09-30T08:00:30.000Z' }, waived:false }],
      counts: { info:0, low:0, medium:0, high:1, critical:0 }, waivedCount:0, reasons:[], audit:[]
    },
    evidence: [{ schemaVersion:'1.0.0', id:'evidence-1', type:'dependency.scan', scanner:'dependencies', repository:'product', commitSha:'abc123', branch:'main', generatedAt:'2026-09-30T08:00:40.000Z', findingIds:['finding-1'], metadata:{} }]
  };
}

test('canonical consumer envelope contains technical facts but no client-domain identifiers', () => {
  const report = fixture();
  const envelope = buildTechnicalFindingEnvelope({
    identity: { tenant:'tenant-a', project:'project-a' }, report, appliedFinding: report.policy.findings[0]!, productVersion:'0.1.0', producedAt:'2026-09-30T08:02:00.000Z'
  });
  assert.equal(envelope.finding.id, 'finding-1');
  assert.deepEqual(envelope.evidenceReference.evidenceIds, ['evidence-1']);
  assert.deepEqual(envelope.evidenceReference.evidenceTypes, ['dependency.scan']);
  assert.equal(envelope.evidenceReference.resourcePath, '/v1/runs/run-1/evidence');
  const json = JSON.stringify(envelope);
  assert.equal(json.includes('assessmentId'), false);
  assert.equal(json.includes('craViolation'), false);
  assert.equal(json.includes('complianceStatus'), false);
});

test('canonical consumer envelope fails closed when authoritative evidence is absent', () => {
  const report = fixture(); report.evidence = [];
  assert.throws(() => buildTechnicalFindingEnvelope({ identity:{tenant:'t',project:'p'}, report, appliedFinding:report.policy.findings[0]!, productVersion:'0.1.0' }), /No authoritative evidence/);
});
