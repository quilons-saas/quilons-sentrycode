import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export interface DetachedSignature {
  schemaVersion: 1;
  algorithm: 'sha256WithKey';
  payloadSha256: string;
  signature: string;
  publicKeyFingerprint: string;
  signedAt: string;
}

function digest(data: Buffer | string): string { return createHash('sha256').update(data).digest('hex'); }

export async function signFile(root: string, file: string, privateKeyFile: string, signatureFile: string): Promise<DetachedSignature> {
  const payload = await readFile(resolve(root, file));
  const key = createPrivateKey(await readFile(resolve(root, privateKeyFile), 'utf8'));
  const publicPem = createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString();
  const detached: DetachedSignature = {
    schemaVersion: 1,
    algorithm: 'sha256WithKey',
    payloadSha256: digest(payload),
    signature: sign('sha256', payload, key).toString('base64'),
    publicKeyFingerprint: digest(publicPem),
    signedAt: new Date().toISOString()
  };
  const target = resolve(root, signatureFile);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(detached, null, 2)}\n`, 'utf8');
  return detached;
}

export async function verifyFile(root: string, file: string, signatureFile: string, publicKeyFile: string): Promise<boolean> {
  const payload = await readFile(resolve(root, file));
  const detached = JSON.parse(await readFile(resolve(root, signatureFile), 'utf8')) as DetachedSignature;
  if (detached.schemaVersion !== 1 || detached.algorithm !== 'sha256WithKey' || detached.payloadSha256 !== digest(payload)) return false;
  const key = createPublicKey(await readFile(resolve(root, publicKeyFile), 'utf8'));
  return verify('sha256', payload, key, Buffer.from(detached.signature, 'base64'));
}

export async function sha256File(path: string): Promise<string> { return digest(await readFile(path)); }
