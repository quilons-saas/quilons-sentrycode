import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import type { ConsumerConfig, ScanReport, ScannerPlugin } from '../src/core/types.js';
import { buildConsumerDeliveryMessages } from '../src/consumers/messages.js';
import { buildCraFindingReport } from '../src/compliance/cra-reporting.js';
import { buildTechnicalFindingEnvelope } from '../src/consumers/envelope.js';
import { CraConsumerAdapter } from '../src/consumers/cra-adapter.js';
import { requiredScannerUnion } from '../src/consumers/registry.js';
import { runScan } from '../src/core/engine.js';

function reportFixture(): ScanReport {
  return {
    schemaVersion:'1.0.0',runId:'run-shared',startedAt:'2026-09-30T10:00:00.000Z',completedAt:'2026-09-30T10:00:05.000Z',
    repository:{root:'/repo',repository:'payments',commitSha:'abc123',branch:'main',isDirty:false},scanners:[],
    policy:{decision:'FAIL',findings:[
      {waived:false,finding:{schemaVersion:'1.0.0',id:'critical-vuln',type:'vulnerability',scanner:'dependencies',ruleId:'CVE-1',title:'Critical vulnerability',description:'critical',severity:'critical',fingerprint:'fp1',detectedAt:'2026-09-30T10:00:02.000Z'}},
      {waived:false,finding:{schemaVersion:'1.0.0',id:'high-secret',type:'secret',scanner:'secrets',ruleId:'secret.token',title:'Secret',description:'high',severity:'high',fingerprint:'fp2',detectedAt:'2026-09-30T10:00:03.000Z'}}
    ],counts:{info:0,low:0,medium:0,high:1,critical:1},waivedCount:0,reasons:[],audit:[]},
    evidence:[
      {schemaVersion:'1.0.0',id:'e-vuln',type:'vuln.scan',scanner:'dependencies',repository:'payments',commitSha:'abc123',branch:'main',generatedAt:'2026-09-30T10:00:02.000Z',findingIds:['critical-vuln'],metadata:{}},
      {schemaVersion:'1.0.0',id:'e-secret',type:'secret.scan',scanner:'secrets',repository:'payments',commitSha:'abc123',branch:'main',generatedAt:'2026-09-30T10:00:03.000Z',findingIds:['high-secret'],metadata:{}}
    ],
    execution:{mode:'full',changedFiles:[],ci:{provider:'github',detected:true,pullRequest:true,buildId:'ci-build',jobId:'job-1'}}
  };
}

function consumer(consumerId:string,adapter:string,requiredScanners:string[],severities:ConsumerConfig['scanProfile']['severities'],context:Record<string,string>):ConsumerConfig {
  return {consumerId,adapter,enabled:true,endpoint:`https://${consumerId}.example/api`,tokenEnv:'',timeoutMs:1000,maxAttempts:3,retryDelayMs:1000,scanProfile:{requiredScanners,evidenceTypes:[],severities,findingTypes:[]},context};
}

test('CRA and Cyber fan out from one normalized run with independent selection and CRA mapping equivalence',()=>{
  const report=reportFixture();
  const identity={tenant:'tenant-a',project:'project-a'};
  const cra=consumer('cra','cra',['dependencies'],['critical'],{assessmentId:'assessment-1'});
  const cyber=consumer('cyber','cyber',['dependencies','secrets'],['high','critical'],{buildId:'cyber-build'});
  const craMessages=buildConsumerDeliveryMessages({consumer:cra,identity,report,productVersion:'0.1.0',producedAt:'2026-09-30T10:00:06.000Z'});
  const cyberMessages=buildConsumerDeliveryMessages({consumer:cyber,identity,report,productVersion:'0.1.0',producedAt:'2026-09-30T10:00:06.000Z'});
  assert.equal(craMessages.length,1);
  assert.equal(cyberMessages.length,2);
  assert.ok([...craMessages,...cyberMessages].every((item)=>item.runId==='run-shared'));
  assert.equal(craMessages[0]!.adapterContractVersion,'1.0.0');
  assert.equal(cyberMessages[0]!.adapterContractVersion,'cyber.security-evidence.v1');

  const applied=report.policy.findings[0]!;
  const envelope=buildTechnicalFindingEnvelope({identity,report,appliedFinding:applied,productVersion:'0.1.0',producedAt:'2026-09-30T10:00:06.000Z'});
  const adapterMapped=new CraConsumerAdapter().mapFinding(envelope,cra);
  const legacyMapped=buildCraFindingReport({identity,report,appliedFinding:applied,productVersion:'0.1.0',reportedAt:'2026-09-30T10:00:06.000Z'});
  assert.deepEqual(adapterMapped,legacyMapped);
  assert.equal(craMessages[0]!.messageId,legacyMapped.reportId);
  assert.equal(JSON.stringify(envelope).includes('assessmentId'),false);
  assert.equal(JSON.stringify(envelope).includes('cyber-build'),false);
});

test('enabled consumer scanner requirements form one deterministic union',()=>{
  const config=structuredClone(DEFAULT_CONFIG);
  config.policy.requiredScanners=['sast'];
  config.consumers=[
    consumer('cra','cra',['dependencies','secrets'],[],{assessmentId:'assessment-1'}),
    consumer('cyber','cyber',['provenance','dependencies'],[],{buildId:'build-1'})
  ];
  assert.deepEqual(requiredScannerUnion(config),['dependencies','provenance','sast','secrets']);
});



test('two enabled consumers reuse one scanner execution for one repository revision',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-scan-once-'));
  const config=structuredClone(DEFAULT_CONFIG);
  config.policy.requiredScanners=[];
  config.consumers=[
    consumer('cra','cra',['counting'],[],{assessmentId:'assessment-1'}),
    consumer('cyber','cyber',['counting'],[],{buildId:'build-1'})
  ];
  let calls=0;
  const scanner:ScannerPlugin={
    id:'counting',version:'1.0.0',
    async scan(context){
      calls+=1;
      const at=context.now().toISOString();
      return {scanner:'counting',durationMs:1,status:'success',findings:[{schemaVersion:'1.0.0',id:'finding-counting',type:'technical',scanner:'counting',ruleId:'counting.rule',title:'Technical finding',description:'technical',severity:'high',fingerprint:'counting-fp',detectedAt:at}],evidence:[{schemaVersion:'1.0.0',id:'e-counting',type:'counting.scan',scanner:'counting',repository:context.repository.repository,commitSha:context.repository.commitSha,branch:context.repository.branch,generatedAt:at,findingIds:['finding-counting'],metadata:{}}]};
    }
  };
  const report=await runScan({repository:{root,repository:'repo',commitSha:'abc',branch:'main',isDirty:false},config,scanners:[scanner],now:()=>new Date('2026-09-30T10:00:00.000Z')});
  assert.equal(calls,1);
  const identity={tenant:'tenant-a',project:'project-a'};
  const craMessages=buildConsumerDeliveryMessages({consumer:config.consumers[0]!,identity,report,productVersion:'0.1.0',producedAt:'2026-09-30T10:00:01.000Z'});
  const cyberMessages=buildConsumerDeliveryMessages({consumer:config.consumers[1]!,identity,report,productVersion:'0.1.0',producedAt:'2026-09-30T10:00:01.000Z'});
  assert.equal(craMessages.length,1);
  assert.equal(cyberMessages.length,1);
  assert.equal(craMessages[0]!.runId,report.runId);
  assert.equal(cyberMessages[0]!.runId,report.runId);
});

test('zero consumers preserve the standalone scanner policy',()=>{
  const config=structuredClone(DEFAULT_CONFIG);
  config.consumers=[];
  config.craReporting.enabled=false;
  config.policy.requiredScanners=['secrets'];
  assert.deepEqual(requiredScannerUnion(config),['secrets']);
});

test('consumer scan-plan evidence is auditable and missing requested capability fails closed',async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-acceptance-'));
  const config=structuredClone(DEFAULT_CONFIG);
  config.policy.requiredScanners=[];
  config.consumers=[consumer('cyber','cyber',['runtime-security-sensor'],[],{buildId:'build-1'})];
  const report=await runScan({repository:{root,repository:'repo',commitSha:'abc',branch:'main',isDirty:false},config,scanners:[],now:()=>new Date('2026-09-30T10:00:00.000Z')});
  assert.equal(report.policy.decision,'FAIL');
  assert.ok(report.policy.reasons.some((reason)=>reason.includes('runtime-security-sensor')));
  const evidence=report.evidence.find((item)=>item.type==='policy.eval');
  assert.ok(evidence);
  assert.equal(evidence.metadata.consumerRequiredScanners,'runtime-security-sensor');
  assert.deepEqual(JSON.parse(String(evidence.metadata.consumerPlan)),[{consumerId:'cyber',adapter:'cyber',adapterAvailable:true,adapterContractVersion:'cyber.security-evidence.v1',requiredScanners:['runtime-security-sensor'],evidenceTypes:[]}]);
});
