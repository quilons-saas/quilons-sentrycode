import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { complianceIdentity } from '../src/compliance/scope.js';
import { buildPublication } from '../src/compliance/publication.js';
import { SentryCodeComplianceService } from '../src/compliance/service.js';
import { startComplianceServer } from '../src/compliance/server.js';
import type { ScanReport } from '../src/core/types.js';

function report(): ScanReport {
  return {
    schemaVersion: '1.0.0',
    runId: 'run-direct-evidence',
    startedAt: '2026-08-31T06:00:00.000Z',
    completedAt: '2026-08-31T06:00:01.000Z',
    repository: { root: '/repo', repository: 'example/repo', commitSha: 'abc123', branch: 'main', isDirty: false },
    scanners: [],
    policy: {
      decision: 'FAIL',
      findings: [],
      counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
      waivedCount: 0,
      reasons: ['material technical finding'],
      audit: [],
      effectivePolicy: { sourceDocuments: [], failOn: ['high','critical'], warnOn: ['medium'], requiredScanners: [], scannerFailureModes: {}, lockedFields: [], fingerprint: 'policy-direct' }
    },
    evidence: [
      { schemaVersion: '1.0.0', id: 'evidence-vuln-1', type: 'vuln.scan', scanner: 'dependencies', repository: 'example/repo', commitSha: 'abc123', branch: 'main', generatedAt: '2026-08-31T06:00:01.000Z', findingIds: ['finding-1'], metadata: { findingCount: 1 } },
      { schemaVersion: '1.0.0', id: 'evidence-policy-1', type: 'policy.eval', scanner: 'policy', repository: 'example/repo', commitSha: 'abc123', branch: 'main', generatedAt: '2026-08-31T06:00:01.000Z', findingIds: [], metadata: { decision: 'FAIL' } }
    ]
  };
}

test('Compliance service resolves one authoritative evidence record by ID through existing verified run path', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-evidence-by-id-'));
  await writeFile(join(root, 'package.json'), JSON.stringify({ version: '0.1.0' }));
  const service = new SentryCodeComplianceService(root, '.sentrycode/compliance');
  const identity = complianceIdentity('tenant-a', 'project-a');
  await service.store.publish(identity, buildPublication(identity, report(), '0.1.0'));

  const evidence = await service.getEvidenceById(identity, 'run-direct-evidence', 'evidence-vuln-1');
  assert.equal(evidence?.id, 'evidence-vuln-1');
  assert.equal(evidence?.type, 'vuln.scan');
  assert.equal(await service.getEvidenceById(identity, 'run-direct-evidence', 'missing-evidence'), null);
  assert.equal(await service.getEvidenceById(complianceIdentity('tenant-b', 'project-a'), 'run-direct-evidence', 'evidence-vuln-1'), null);
});

test('Compliance API returns a specific evidence record while retaining the bulk evidence endpoint', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-evidence-api-'));
  await writeFile(join(root, 'package.json'), JSON.stringify({ version: '0.1.0' }));
  const service = new SentryCodeComplianceService(root, '.sentrycode/compliance');
  const identity = complianceIdentity('tenant-a', 'project-a');
  await service.store.publish(identity, buildPublication(identity, report(), '0.1.0'));
  const running = await startComplianceServer(service, { host: '127.0.0.1', port: 0, token: 'test-token' });

  try {
    const base = `http://127.0.0.1:${running.port}`;
    const query = '?tenant=tenant-a&project=project-a';
    const headers = { authorization: 'Bearer test-token' };

    const direct = await fetch(`${base}/v1/runs/run-direct-evidence/evidence/evidence-vuln-1${query}`, { headers });
    assert.equal(direct.status, 200);
    const directEvidence = await direct.json() as { id: string; type: string };
    assert.equal(directEvidence.id, 'evidence-vuln-1');
    assert.equal(directEvidence.type, 'vuln.scan');

    const bulk = await fetch(`${base}/v1/runs/run-direct-evidence/evidence${query}`, { headers });
    assert.equal(bulk.status, 200);
    const envelope = await bulk.json() as { evidence: Array<{ id: string }> };
    assert.deepEqual(envelope.evidence.map((item) => item.id), ['evidence-vuln-1', 'evidence-policy-1']);

    const missing = await fetch(`${base}/v1/runs/run-direct-evidence/evidence/missing-evidence${query}`, { headers });
    assert.equal(missing.status, 404);
    assert.deepEqual(await missing.json(), { error: 'evidence_not_found' });
  } finally {
    await new Promise<void>((resolve, reject) => running.server.close((error?: Error) => error ? reject(error) : resolve()));
  }
});
