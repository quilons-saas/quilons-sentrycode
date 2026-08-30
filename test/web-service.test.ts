import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { complianceIdentity } from '../src/compliance/scope.js';
import { LocalComplianceStore } from '../src/compliance/store.js';
import { SentryCodeWebService } from '../src/web/service.js';
import type { CompliancePublication } from '../src/compliance/contracts.js';

function publication(): CompliancePublication {
  return {
    summary: { runId:'run-ui-1', tenant:'tenant-a', project:'project-a', repository:'demo/repo', commitSha:'abcdef1234567890', branch:'main', decision:'FAIL', startedAt:'2026-08-29T08:00:00.000Z', completedAt:'2026-08-29T08:00:01.000Z', evidenceCount:1, findingCount:1 },
    evidence: { schemaVersion:1, apiVersion:'1.0.0', producer:{ pluginId:'quilons.sentrycode', product:'QUILONS SentryCode', version:'0.1.0' }, tenant:'tenant-a', project:'project-a', repository:'demo/repo', runId:'run-ui-1', decision:'FAIL', generatedAt:'2026-08-29T08:00:01.000Z', evidence:[{ schemaVersion:'1.0.0', id:'ev-1', type:'secret.scan', scanner:'secrets', repository:'demo/repo', commitSha:'abcdef1234567890', branch:'main', generatedAt:'2026-08-29T08:00:01.000Z', findingIds:['f-1'], metadata:{} }] },
    report: { schemaVersion:'1.0.0', runId:'run-ui-1', startedAt:'2026-08-29T08:00:00.000Z', completedAt:'2026-08-29T08:00:01.000Z', repository:{ root:'.', repository:'demo/repo', commitSha:'abcdef1234567890', branch:'main', isDirty:false }, scanners:[{ scanner:'secrets', findings:[], evidence:[], durationMs:10, status:'success' }], policy:{ decision:'FAIL', findings:[{ finding:{ schemaVersion:'1.0.0', id:'f-1', type:'secret', scanner:'secrets', ruleId:'secret.test', title:'Test secret', description:'redacted', severity:'critical', fingerprint:'fp-1', detectedAt:'2026-08-29T08:00:00.500Z' }, waived:false }], counts:{info:0,low:0,medium:0,high:0,critical:1}, waivedCount:0, reasons:['critical finding'], audit:[] }, evidence:[] },
    events: []
  };
}

test('standalone web service derives dashboard and repository views from verified store', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-web-'));
  await writeFile(join(root,'package.json'),'{}');
  const config = structuredClone(DEFAULT_CONFIG);
  config.compliance.storeDirectory = '.sentrycode/compliance';
  const identity = complianceIdentity('tenant-a','project-a');
  const store = new LocalComplianceStore(root, config.compliance.storeDirectory);
  await store.publish(identity, publication());
  const service = new SentryCodeWebService(root, config, identity);
  const dashboard = await service.dashboard();
  assert.equal(dashboard.runs,1);
  assert.equal(dashboard.repositories,1);
  assert.equal(dashboard.decisions.FAIL,1);
  assert.equal(dashboard.findings.critical,1);
  const repositories = await service.repositories();
  assert.equal(repositories[0]?.repository,'demo/repo');
  const detail = await service.runDetail('run-ui-1');
  assert.equal(detail?.integrity.verified,true);
  assert.equal(detail?.report.findings[0]?.finding.title,'Test secret');
});

test('standalone web service refuses run browsing when no scope is configured', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-web-noscope-'));
  await writeFile(join(root,'package.json'),'{}');
  const service = new SentryCodeWebService(root, structuredClone(DEFAULT_CONFIG), null);
  await assert.rejects(() => service.listRuns(), /UI_SCOPE_NOT_CONFIGURED/);
  const status = await service.status();
  assert.equal(status.ready,false);
});
