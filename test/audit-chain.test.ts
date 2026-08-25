import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendAuditEvent, verifyAuditChain } from '../src/enterprise/audit.js';

test('audit hash chain detects event rewriting',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-audit-')); const file='.sentrycode/audit/events.jsonl';
  await appendAuditEvent(root,file,'one',{value:1},'tester'); await appendAuditEvent(root,file,'two',{value:2},'tester'); assert.equal((await verifyAuditChain(root,file)).ok,true);
  const absolute=join(root,file); const content=await readFile(absolute,'utf8'); await writeFile(absolute,content.replace('"value":1','"value":9'));
  assert.equal((await verifyAuditChain(root,file)).ok,false);
});

import { generateKeyPairSync } from 'node:crypto';
test('signed audit chain requires trusted public key signatures',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-signed-audit-')); const file='.sentrycode/audit/events.jsonl'; const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}}); await writeFile(join(root,'private.pem'),privateKey); await writeFile(join(root,'public.pem'),publicKey);
  await appendAuditEvent(root,file,'signed',{value:1},'tester','private.pem'); assert.equal((await verifyAuditChain(root,file,'public.pem')).ok,true);
  const content=await readFile(join(root,file),'utf8'); const event=JSON.parse(content) as {signature:string}; event.signature='AAAA'; await writeFile(join(root,file),`${JSON.stringify(event)}\n`); assert.equal((await verifyAuditChain(root,file,'public.pem')).ok,false);
});
