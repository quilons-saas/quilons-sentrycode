import test from 'node:test';
import assert from 'node:assert/strict';
import { CyberConsumerAdapter } from '../src/consumers/cyber-adapter.js';
import type { ConsumerConfig } from '../src/core/types.js';
import type { TechnicalFindingEnvelope } from '../src/consumers/contracts.js';

function config(): ConsumerConfig { return {consumerId:'cyber',adapter:'cyber',enabled:true,endpoint:'https://cyber.example/api/v1/invoke',tokenEnv:'CYBER_TOKEN',timeoutMs:1000,maxAttempts:3,retryDelayMs:0,scanProfile:{requiredScanners:['dependencies'],evidenceTypes:[],severities:[],findingTypes:[]},context:{buildId:'build-1'}}; }
function envelope(): TechnicalFindingEnvelope { return {schemaVersion:1,contractVersion:'1.0.0',messageId:'msg-1',source:{pluginId:'quilons.sentrycode',product:'QUILONS SentryCode',version:'0.1.0'},tenant:'tenant-a',project:'project-a',repository:'repo',finding:{id:'finding-1',type:'vulnerability',scanner:'dependencies',ruleId:'CVE-X',title:'Issue',description:'Technical issue',severity:'high',status:'active'},sourceRevision:{commitSha:'abc',branch:'main'},evidenceReference:{apiVersion:'1.0.0',runId:'run-1',evidenceIds:['e1'],evidenceTypes:['dependency.scan'],resourcePath:'/v1/runs/run-1/evidence'},correlation:{runId:'run-1'},timestamps:{detectedAt:'2026-09-30T10:00:00.000Z',scanCompletedAt:'2026-09-30T10:01:00.000Z',producedAt:'2026-09-30T10:02:00.000Z'}}; }

test('Cyber adapter maps a neutral technical finding into the existing Cyber security-evidence contract',()=>{
  const mapped=new CyberConsumerAdapter().mapFinding(envelope(),config());
  assert.equal(mapped.operation,'cyber.security-evidence.ingest');
  assert.equal(mapped.tenantId,'tenant-a');
  assert.equal(mapped.input.submission.evidenceType,'EXTERNAL_TOOL_RESULT');
  assert.equal(mapped.input.submission.subject.subjectType,'BUILD');
  assert.equal(mapped.input.submission.subject.subjectId,'build-1');
  assert.equal(mapped.input.submission.provider.providerId,'quilons-sentrycode');
  assert.deepEqual(mapped.input.submission.normalizedPayload.evidenceReference,{apiVersion:'1.0.0',runId:'run-1',evidenceIds:['e1'],evidenceTypes:['dependency.scan'],resourcePath:'/v1/runs/run-1/evidence'});
  const json=JSON.stringify(mapped);
  assert.equal(json.includes('assessmentId'),false);
  assert.equal(json.includes('craViolation'),false);
});

test('Cyber adapter requires an explicit Cyber build binding and validates assurance context',()=>{
  const adapter=new CyberConsumerAdapter(); const c=config(); c.context={};
  assert.throws(()=>adapter.mapFinding(envelope(),c),/context.buildId is required/);
  c.context={buildId:'build-1',assuranceContext:'invalid'};
  assert.throws(()=>adapter.mapFinding(envelope(),c),/assuranceContext must be MANUFACTURER or DEPLOYMENT/);
});
