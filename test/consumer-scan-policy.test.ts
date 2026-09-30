import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { runScan } from '../src/core/engine.js';

test('enabled consumer scanner requirements form a fail-closed floor under repository policy', async()=>{
  const root=await mkdtemp(join(tmpdir(),'consumer-scan-policy-'));
  const config=structuredClone(DEFAULT_CONFIG);
  config.policy.requiredScanners=[];
  config.consumers=[{consumerId:'cyber',adapter:'cyber',enabled:true,endpoint:'https://cyber.example',tokenEnv:'',timeoutMs:1,maxAttempts:1,retryDelayMs:0,scanProfile:{requiredScanners:['dependencies'],evidenceTypes:[],severities:[],findingTypes:[]},context:{buildId:'build-1'}}];
  const report=await runScan({repository:{root,repository:'repo',commitSha:'abc',branch:'main',isDirty:false},config,scanners:[],now:()=>new Date('2026-09-30T10:00:00.000Z')});
  assert.deepEqual(report.policy.effectivePolicy?.requiredScanners,['dependencies']);
  assert.equal(report.policy.decision,'FAIL');
  assert.ok(report.policy.reasons.some((reason)=>reason.includes('dependencies')));
});
