import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ConsumerDeliveryEnqueueResult, ConsumerDeliveryRecord } from '../src/application/types.js';
import { deliverPendingConsumerDeliveries, enqueueConsumerDeliveries, type ConsumerDeliveryMessage, type ConsumerPayloadPublisher } from '../src/consumers/delivery.js';

class MemoryConsumerDeliveryStore {
  values = new Map<string,ConsumerDeliveryRecord>();
  private key(consumerId:string,messageId:string){return `${consumerId}|${messageId}`;}
  async enqueueConsumerDelivery(value: Pick<ConsumerDeliveryRecord,'consumerId'|'adapterId'|'adapterContractVersion'|'messageId'|'tenant'|'project'|'findingId'|'runId'|'payload'>): Promise<ConsumerDeliveryEnqueueResult> {
    const key=this.key(value.consumerId,value.messageId); const existing=this.values.get(key); if(existing) return {record:existing,created:false};
    const now='2026-09-30T10:00:00.000Z';
    const record:ConsumerDeliveryRecord={...value,status:'pending',attemptCount:0,responseStatus:null,lastAttemptAt:null,nextAttemptAt:null,lastError:null,deliveredAt:null,createdAt:now,updatedAt:now};
    this.values.set(key,record); return {record,created:true};
  }
  async listPendingConsumerDeliveries(consumerId:string,tenant:string,project:string,maxAttempts:number,now:string,limit=100):Promise<ConsumerDeliveryRecord[]> {
    const at=Date.parse(now); return [...this.values.values()].filter(v=>v.consumerId===consumerId&&v.tenant===tenant&&v.project===project&&v.status!=='delivered'&&v.attemptCount<maxAttempts&&(!v.nextAttemptAt||Date.parse(v.nextAttemptAt)<=at)).slice(0,limit);
  }
  async recordConsumerDeliveryAttempt(consumerId:string,messageId:string,value:{delivered:boolean;responseStatus?:number;error?:string;nextAttemptAt?:string}):Promise<ConsumerDeliveryRecord|null>{
    const key=this.key(consumerId,messageId); const old=this.values.get(key); if(!old||old.status==='delivered') return null;
    const next:ConsumerDeliveryRecord={...old,status:value.delivered?'delivered':'failed',attemptCount:old.attemptCount+1,responseStatus:value.responseStatus??null,lastAttemptAt:'2026-09-30T10:00:01.000Z',nextAttemptAt:value.delivered?null:(value.nextAttemptAt??null),lastError:value.delivered?null:(value.error??null),deliveredAt:value.delivered?'2026-09-30T10:00:01.000Z':old.deliveredAt,updatedAt:'2026-09-30T10:00:01.000Z'};
    this.values.set(key,next); return next;
  }
}

class Publisher implements ConsumerPayloadPublisher {
  calls:string[]=[];
  constructor(private readonly name:string,private readonly fail=false){}
  async publish(payload:Record<string,unknown>){this.calls.push(String(payload.id));if(this.fail)throw new Error(`${this.name} unavailable`);return{statusCode:202};}
}

function message(consumerId:string,id:string):ConsumerDeliveryMessage{return{consumerId,adapterId:consumerId,adapterContractVersion:'1.0.0',messageId:`${consumerId}-${id}`,tenant:'acme',project:'payments',findingId:id,runId:'run-1',payload:{id,consumerId}};}

test('generic consumer delivery is idempotent per consumer and permits the same finding for multiple consumers',async()=>{
  const store=new MemoryConsumerDeliveryStore();
  const first=await enqueueConsumerDeliveries(store,[message('cra','finding-1'),message('cyber','finding-1')]);
  const duplicate=await enqueueConsumerDeliveries(store,[message('cra','finding-1')]);
  assert.equal(first.filter(x=>x.created).length,2); assert.equal(duplicate[0]!.created,false); assert.equal(store.values.size,2);
});

test('consumer failure is isolated and does not block delivery to another consumer',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-delivery-')); const store=new MemoryConsumerDeliveryStore();
  await enqueueConsumerDeliveries(store,[message('cra','finding-1'),message('cyber','finding-1')]);
  const craPublisher=new Publisher('CRA'); const cyberPublisher=new Publisher('Cyber',true);
  const cra=await deliverPendingConsumerDeliveries({store,publisher:craPublisher,consumerId:'cra',tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-09-30T10:00:01.000Z')});
  const cyber=await deliverPendingConsumerDeliveries({store,publisher:cyberPublisher,consumerId:'cyber',tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:1000},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-09-30T10:00:01.000Z')});
  assert.deepEqual(cra,{attempted:1,delivered:1,failed:0}); assert.deepEqual(cyber,{attempted:1,delivered:0,failed:1});
  assert.equal(store.values.get('cra|cra-finding-1')!.status,'delivered'); assert.equal(store.values.get('cyber|cyber-finding-1')!.status,'failed');
  const audit=await readFile(join(root,'.sentrycode/audit/events.jsonl'),'utf8'); assert.match(audit,/consumer\.delivery\.delivered/); assert.match(audit,/consumer\.delivery\.delivery_failed/);
});

test('retry and max-attempt policy are scoped independently per consumer',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-retry-')); const store=new MemoryConsumerDeliveryStore(); await enqueueConsumerDeliveries(store,[message('cyber','finding-2')]);
  await deliverPendingConsumerDeliveries({store,publisher:new Publisher('Cyber',true),consumerId:'cyber',tenant:'acme',project:'payments',options:{maxAttempts:1,retryDelayMs:0},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-09-30T10:00:01.000Z')});
  const second=await deliverPendingConsumerDeliveries({store,publisher:new Publisher('Cyber'),consumerId:'cyber',tenant:'acme',project:'payments',options:{maxAttempts:1,retryDelayMs:0},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-09-30T10:00:02.000Z')});
  assert.equal(second.attempted,0); assert.equal(store.values.get('cyber|cyber-finding-2')!.attemptCount,1);
});

test('CRA compatibility can retain historical audit event names on the generic engine',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-cra-audit-')); const store=new MemoryConsumerDeliveryStore(); await enqueueConsumerDeliveries(store,[message('cra','finding-3')]);
  await deliverPendingConsumerDeliveries({store,publisher:new Publisher('CRA'),consumerId:'cra',tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:0},root,auditLogFile:'.sentrycode/audit/events.jsonl',auditEventPrefix:'cra.report',now:new Date('2026-09-30T10:00:01.000Z')});
  const audit=await readFile(join(root,'.sentrycode/audit/events.jsonl'),'utf8'); assert.match(audit,/cra\.report\.delivered/);
});


test('generic delivery fails closed when an idempotency key is reused for different delivery content',async()=>{
  const store=new MemoryConsumerDeliveryStore();
  await enqueueConsumerDeliveries(store,[message('cra','finding-4')]);
  const collision={...message('cra','finding-4'),tenant:'other-tenant'};
  await assert.rejects(()=>enqueueConsumerDeliveries(store,[collision]),/idempotency collision/);
});

test('healthy consumer delivery drains more than one storage batch in one governed invocation',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-multipage-')); const store=new MemoryConsumerDeliveryStore();
  const messages=Array.from({length:205},(_,index)=>message('cra',`finding-${index+1}`));
  await enqueueConsumerDeliveries(store,messages);
  const publisher=new Publisher('CRA');
  const result=await deliverPendingConsumerDeliveries({store,publisher,consumerId:'cra',tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:1000,batchSize:100},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-09-30T10:00:01.000Z')});
  assert.deepEqual(result,{attempted:205,delivered:205,failed:0});
  assert.equal(publisher.calls.length,205);
  assert.equal([...store.values.values()].filter(value=>value.status==='delivered').length,205);
});

test('consumer delivery stops the current drain cycle after a failed page without immediate self-retry',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-failed-page-')); const store=new MemoryConsumerDeliveryStore();
  const messages=Array.from({length:101},(_,index)=>message('cyber',`finding-${index+1}`));
  await enqueueConsumerDeliveries(store,messages);
  const publisher=new Publisher('Cyber',true);
  const result=await deliverPendingConsumerDeliveries({store,publisher,consumerId:'cyber',tenant:'acme',project:'payments',options:{maxAttempts:3,retryDelayMs:0,batchSize:100},root,auditLogFile:'.sentrycode/audit/events.jsonl',now:new Date('2026-09-30T10:00:01.000Z')});
  assert.deepEqual(result,{attempted:100,delivered:0,failed:100});
  assert.equal(publisher.calls.length,100);
  assert.equal(store.values.get('cyber|cyber-finding-1')!.attemptCount,1);
  assert.equal(store.values.get('cyber|cyber-finding-101')!.attemptCount,0);
});
