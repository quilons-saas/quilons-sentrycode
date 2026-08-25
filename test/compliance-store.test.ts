import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { complianceIdentity, scopeKey } from '../src/compliance/scope.js';
import { LocalComplianceStore } from '../src/compliance/store.js';
import { buildPublication } from '../src/compliance/publication.js';
import type { ScanReport } from '../src/core/types.js';

function report(): ScanReport {
  return {
    schemaVersion: '1.0.0', runId: 'run-1', startedAt: '2026-08-25T10:00:00.000Z', completedAt: '2026-08-25T10:00:01.000Z',
    repository: { root: '/repo', repository: 'example/repo', commitSha: 'abc', branch: 'main', isDirty: false },
    scanners: [],
    policy: { decision: 'PASS', findings: [], counts: { info:0,low:0,medium:0,high:0,critical:0 }, waivedCount: 0, reasons: [], audit: [], effectivePolicy: { sourceDocuments: [], failOn:['high','critical'], warnOn:['medium'], requiredScanners:[], scannerFailureModes:{}, lockedFields:[], fingerprint:'policy-1' } },
    evidence: [{ schemaVersion:'1.0.0', id:'e1', type:'policy.eval', scanner:'policy', repository:'example/repo', commitSha:'abc', branch:'main', generatedAt:'2026-08-25T10:00:01.000Z', findingIds:[], metadata:{ decision:'PASS' } }]
  };
}

test('tenant/project scope keys are stable and isolated', () => {
  assert.equal(scopeKey(complianceIdentity('tenant-a','project-a')), scopeKey(complianceIdentity('tenant-a','project-a')));
  assert.notEqual(scopeKey(complianceIdentity('tenant-a','project-a')), scopeKey(complianceIdentity('tenant-b','project-a')));
});

test('local compliance store prevents cross-scope run retrieval', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-store-'));
  const store = new LocalComplianceStore(root, '.sentrycode/compliance');
  const a = complianceIdentity('tenant-a','project-a');
  const b = complianceIdentity('tenant-b','project-a');
  await store.publish(a, buildPublication(a, report(), '0.1.0'));
  assert.ok(await store.getPublication(a, 'run-1'));
  assert.equal(await store.getPublication(b, 'run-1'), null);
  assert.equal((await store.listRuns(a)).length, 1);
  assert.equal((await store.listRuns(b)).length, 0);
  await assert.rejects(store.publish(a, buildPublication(a, report(), '0.1.0')), /immutable and already exists/);
});

test('publication scope mismatch is rejected', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-store-mismatch-'));
  const store = new LocalComplianceStore(root, '.sentrycode/compliance');
  const a = complianceIdentity('tenant-a','project-a');
  const b = complianceIdentity('tenant-b','project-b');
  const publication = buildPublication(a, report(), '0.1.0');
  await assert.rejects(store.publish(b, publication), /scope mismatch/);
});
