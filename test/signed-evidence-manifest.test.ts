import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalComplianceStore } from '../src/compliance/store.js';
import { complianceIdentity, tenantStoreRoot } from '../src/compliance/scope.js';
import { buildPublication } from '../src/compliance/publication.js';
import type { ScanReport } from '../src/core/types.js';
function report():ScanReport{return {schemaVersion:'1.0.0',runId:'signed-run',startedAt:'2026-08-25T00:00:00.000Z',completedAt:'2026-08-25T00:00:01.000Z',repository:{root:'/r',repository:'r',commitSha:'a',branch:'main',isDirty:false},scanners:[],policy:{decision:'PASS',findings:[],counts:{info:0,low:0,medium:0,high:0,critical:0},waivedCount:0,reasons:[],audit:[]},evidence:[]};}

test('signed evidence manifest prevents attacker from replacing both evidence and checksum manifest',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-signed-evidence-')); const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
  await writeFile(join(root,'private.pem'),privateKey); await writeFile(join(root,'public.pem'),publicKey); const identity=complianceIdentity('t','p'); const store=new LocalComplianceStore(root,'.sentrycode/compliance',{privateKeyFile:'private.pem',publicKeyFile:'public.pem'}); await store.publish(identity,buildPublication(identity,report(),'0.1.0')); assert.ok(await store.getPublication(identity,'signed-run'));
  const runDir=join(tenantStoreRoot(root,'.sentrycode/compliance',identity),'runs','signed-run'); const manifest=JSON.parse(await readFile(join(runDir,'integrity.json'),'utf8')) as {files:Array<{path:string;sha256:string}>}; manifest.files=[]; await writeFile(join(runDir,'integrity.json'),JSON.stringify(manifest));
  await assert.rejects(store.getPublication(identity,'signed-run'),/signed manifest verification/);
});


test('run listing verifies signed integrity before exposing summaries', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-signed-list-'));
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
  await writeFile(join(root, 'private.pem'), privateKey);
  await writeFile(join(root, 'public.pem'), publicKey);
  const identity = complianceIdentity('t', 'p');
  const store = new LocalComplianceStore(root, '.sentrycode/compliance', { privateKeyFile: 'private.pem', publicKeyFile: 'public.pem' });
  await store.publish(identity, buildPublication(identity, report(), '0.1.0'));

  const runDir = join(tenantStoreRoot(root, '.sentrycode/compliance', identity), 'runs', 'signed-run');
  const summaryPath = join(runDir, 'summary.json');
  const summary = JSON.parse(await readFile(summaryPath, 'utf8')) as Record<string, unknown>;
  summary.decision = 'FAIL';
  await writeFile(summaryPath, JSON.stringify(summary));

  await assert.rejects(store.listRuns(identity), /integrity verification/);
});
