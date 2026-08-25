import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signFile, verifyFile } from '../src/enterprise/integrity.js';

test('configuration signing detects tampering', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-integrity-'));
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
  await writeFile(join(root, 'config.json'), '{"schemaVersion":1}\n');
  await writeFile(join(root, 'private.pem'), privateKey);
  await writeFile(join(root, 'public.pem'), publicKey);
  await signFile(root, 'config.json', 'private.pem', 'config.sig.json');
  assert.equal(await verifyFile(root, 'config.json', 'config.sig.json', 'public.pem'), true);
  await writeFile(join(root, 'config.json'), '{"schemaVersion":1,"changed":true}\n');
  assert.equal(await verifyFile(root, 'config.json', 'config.sig.json', 'public.pem'), false);
});
