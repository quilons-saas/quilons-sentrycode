import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CraReportDeliveryEnqueueResult, CraReportDeliveryRecord } from '../src/application/types.js';
import { deliverPendingCraFindingReports, enqueueCraFindingReports, type CraFindingPublisher } from '../src/compliance/cra-delivery.js';
import type { CraFindingReport } from '../src/compliance/cra-reporting.js';

function report(id='cra-1'): CraFindingReport {
  return {
    schemaVersion: 1,
    contractVersion: '1.0.0',
    reportId: id,
    source: { pluginId: 'quilons.sentrycode', product: 'QUILONS SentryCode', version: '0.1.0' },
    tenant: 'acme', project: 'payments', repository: 'repo',
    finding: { id: `finding-${id}`, type: 'vulnerability', scanner: 'dependencies', ruleId: 'CVE-1', title: 'Critical vulnerability', description: 'Technical fact', severity: 'critical', status: 'active' },
    sourceRevision: { commitSha: 'abc', branch: 'main' },
    evidenceReference: { apiVersion: '1.0.0', runId: 'run-1', evidenceIds: ['e-1'], resourcePath: '/v1/runs/run-1/evidence' },
    correlation: { runId: 'run-1' },
    timestamps: { detectedAt: '2026-08-31T01:00:00.000Z', scanCompletedAt: '2026-08-31T01:00:01.000Z', reportedAt: '2026-08-31T01:00:02.000Z' }
  };
}

class MemoryDeliveryStore {
  values = new Map<string,CraReportDeliveryRecord>();
  async enqueueCraReportDelivery(value: Pick<CraReportDeliveryRecord,'reportId'|'tenant'|'project'|'findingId'|'runId'|'payload'>): Promise<CraReportDeliveryEnqueueResult> {
    const existing=this.values.get(value.reportId); if(existing) return {record:existing,created:false};
    const now='2026-08-31T01:00:02.000Z';
    const record:CraReportDeliveryRecord={...value,status:'pending',attemptCount:0,responseStatus:null,lastAttemptAt:null,nextAttemptAt:null,lastError:null,deliveredAt:null,createdAt:now,updatedAt:now};
    this.values.set(value.reportId,record); return {record,created:true};
  }
  async listPendingCraReportDeliveries(tenant:string,project:string,maxAttempts:number,now:string,limit=100):Promise<CraReportDeliveryRecord[]> {
    const at=Date.parse(now); return [...this.values.values()].filter(v=>v.tenant===tenant&&v.project===project&&v.status!=='delivered'&&v.attemptCount<maxAttempts&&(!v.nextAttemptAt||Date.parse(v.nextAttemptAt)<=at)).slice(0,limit);
  }
  async recordCraReportDeliveryAttempt(reportId:string,value:{delivered:boolean;responseStatus?:number;error?:string;nextAttemptAt?:string}):Promise<CraReportDeliveryRecord|null>{
    const old=this.values.get(reportId); if(!old||old.status==='delivered') return null;
    const next:CraReportDeliveryRecord={...old,status:value.delivered?'delivered':'failed',attemptCount:old.attemptCount+1,responseStatus:value.responseStatus??null,lastAttemptAt:'2026-08-31T01:00:03.000Z',nextAttemptAt:value.delivered?null:(value.nextAttemptAt??null),lastError:value.delivered?null:(value.error??null),deliveredAt:value.delivered?'2026-08-31T01:00:03.000Z':old.deliveredAt,updatedAt:'2026-08-31T01:00:03.000Z'};
    this.values.set(reportId,next); return next;
  }
}

class Publisher implements CraFindingPublisher {
  calls:string[]=[];
  constructor(private readonly fail=false){}
  async publish(value:CraFindingReport){this.calls.push(value.reportId); if(this.fail) throw new Error('CRA unavailable'); return {statusCode:202};}
}

test('CRA delivery queue is idempotent and delivered reports are not resent',async()=>{
  const root=await mkdtemp(join(tmpdir(),'cra-delivery-')); const store=new MemoryDeliveryStore(); const value=report();
  const one=await enqueueCraFindingReports(store,[value]); const two=await enqueueCraFindingReports(store,[value]);
  assert.equal(one[0]!.created,true); assert.equal(two[0]!.created,false); assert.equal(store.values.size,1);
  const publisher=new Publisher();
  const result=await deliverPendingCraFindingReports({store,publisher,tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:03.000Z')});
  assert.deepEqual(result,{attempted:1,delivered:1,failed:0}); assert.equal(publisher.calls.length,1); assert.equal(store.values.get(value.reportId)!.status,'delivered');
  const again=await deliverPendingCraFindingReports({store,publisher,tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:04.000Z')});
  assert.equal(again.attempted,0); assert.equal(publisher.calls.length,1);
  const audit=await readFile(join(root,'.sentrycode/audit/events.jsonl'),'utf8'); assert.match(audit,/cra\.report\.delivered/);
});

test('CRA delivery failure is persisted for bounded later retry without rebuilding report',async()=>{
  const root=await mkdtemp(join(tmpdir(),'cra-retry-')); const store=new MemoryDeliveryStore(); const value=report('cra-retry'); await enqueueCraFindingReports(store,[value]);
  const failed=await deliverPendingCraFindingReports({store,publisher:new Publisher(true),tenant:'acme',project:'payments',options:{maxAttempts:2,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:03.000Z')});
  assert.deepEqual(failed,{attempted:1,delivered:0,failed:1}); const afterFailure=store.values.get(value.reportId)!; assert.equal(afterFailure.attemptCount,1); assert.equal(afterFailure.status,'failed'); assert.match(afterFailure.lastError??'',/CRA unavailable/);
  const tooSoon=await deliverPendingCraFindingReports({store,publisher:new Publisher(),tenant:'acme',project:'payments',options:{maxAttempts:2,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:03.500Z')}); assert.equal(tooSoon.attempted,0);
  const recoveredPublisher=new Publisher(); const recovered=await deliverPendingCraFindingReports({store,publisher:recoveredPublisher,tenant:'acme',project:'payments',options:{maxAttempts:2,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:04.000Z')});
  assert.equal(recovered.delivered,1); assert.equal(recoveredPublisher.calls[0],value.reportId); assert.equal(store.values.get(value.reportId)!.attemptCount,2);
});

test('CRA delivery stops selecting records after configured maximum attempts',async()=>{
  const root=await mkdtemp(join(tmpdir(),'cra-max-')); const store=new MemoryDeliveryStore(); const value=report('cra-max'); await enqueueCraFindingReports(store,[value]);
  await deliverPendingCraFindingReports({store,publisher:new Publisher(true),tenant:'acme',project:'payments',options:{maxAttempts:1,retryDelayMs:0},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:03.000Z')});
  const next=await deliverPendingCraFindingReports({store,publisher:new Publisher(),tenant:'acme',project:'payments',options:{maxAttempts:1,retryDelayMs:0},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-08-31T01:00:04.000Z')});
  assert.equal(next.attempted,0); assert.equal(store.values.get(value.reportId)!.attemptCount,1);
});
