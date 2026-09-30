import test from 'node:test';
import assert from 'node:assert/strict';
import type { ConsumerConfig, ScanReport } from '../src/core/types.js';
import { selectConsumerFindings } from '../src/consumers/selection.js';

function report(): ScanReport {
  const finding = { schemaVersion:'1.0.0' as const,id:'f1',type:'vulnerability',scanner:'dependencies',ruleId:'CVE-X',title:'x',description:'x',severity:'high' as const,fingerprint:'fp',detectedAt:'2026-09-30T10:00:00.000Z' };
  return { schemaVersion:'1.0.0',runId:'run',startedAt:'2026-09-30T10:00:00.000Z',completedAt:'2026-09-30T10:01:00.000Z',repository:{root:'/repo',repository:'repo',commitSha:'abc',branch:'main',isDirty:false},scanners:[],policy:{decision:'FAIL',findings:[{finding,waived:false}],counts:{info:0,low:0,medium:0,high:1,critical:0},waivedCount:0,reasons:[],audit:[]},evidence:[{schemaVersion:'1.0.0',id:'e1',type:'dependency.scan',scanner:'dependencies',repository:'repo',commitSha:'abc',branch:'main',generatedAt:'2026-09-30T10:00:30.000Z',findingIds:['f1'],metadata:{}}] };
}
function consumer(): ConsumerConfig { return {consumerId:'cyber',adapter:'cyber',enabled:true,endpoint:'x',tokenEnv:'',timeoutMs:1,maxAttempts:1,retryDelayMs:0,scanProfile:{requiredScanners:[],evidenceTypes:[],severities:[],findingTypes:[]},context:{buildId:'build-1'}}; }

test('empty consumer filters select technical findings and configured filters narrow them',()=>{
  const r=report(); const c=consumer();
  assert.equal(selectConsumerFindings(r,c).length,1);
  c.scanProfile.severities=['critical']; assert.equal(selectConsumerFindings(r,c).length,0);
  c.scanProfile.severities=['high']; c.scanProfile.findingTypes=['VULNERABILITY']; c.scanProfile.evidenceTypes=['DEPENDENCY.SCAN'];
  assert.equal(selectConsumerFindings(r,c).length,1);
  c.scanProfile.evidenceTypes=['sast.scan']; assert.equal(selectConsumerFindings(r,c).length,0);
});
