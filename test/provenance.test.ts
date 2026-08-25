import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildStatement, collectArtifacts, signStatement, verifyAttestation } from '../src/provenance/attestation.js';

test('provenance hashes artifacts and verifies signed statement', async () => {
  const root=await mkdtemp(join(tmpdir(),'sentrycode-prov-')); await writeFile(join(root,'artifact.bin'),'payload');
  const artifacts=await collectArtifacts(root,['artifact.bin']); assert.equal(artifacts.length,1); assert.equal(artifacts[0]?.sha256.length,64);
  const pair=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  await writeFile(join(root,'private.pem'),pair.privateKey); await writeFile(join(root,'public.pem'),pair.publicKey);
  const statement=buildStatement({root,repository:'demo',commitSha:'abc',branch:'main',isDirty:false},artifacts,new Date('2026-08-25T00:00:00Z'));
  const signed=await signStatement(statement,join(root,'private.pem')); assert.equal(signed.algorithm,'sha256WithKey');
  assert.equal(await verifyAttestation(signed,join(root,'public.pem')),true);
  signed.statement.predicate.tampered=true;
  assert.equal(await verifyAttestation(signed,join(root,'public.pem')),false);
});
