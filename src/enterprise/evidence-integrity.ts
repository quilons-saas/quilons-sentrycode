import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { sha256File } from './integrity.js';
import { sha256 } from '../utils/hash.js';

export interface IntegrityManifest {
  schemaVersion: 1;
  generatedAt: string;
  files: Array<{ path: string; sha256: string }>;
}
export interface IntegrityManifestSignature {
  schemaVersion: 1;
  algorithm: 'sha256';
  manifestSha256: string;
  signature: string;
  signedAt: string;
}

function canonical(manifest: IntegrityManifest): string { return JSON.stringify(manifest); }

export async function writeIntegrityManifest(directory: string, output = 'integrity.json'): Promise<IntegrityManifest> {
  const names = (await readdir(directory)).filter((name) => name !== output && name !== `${output}.sig`).sort();
  const files: IntegrityManifest['files'] = [];
  for (const name of names) files.push({ path: basename(name), sha256: await sha256File(resolve(directory, name)) });
  const manifest: IntegrityManifest = { schemaVersion: 1, generatedAt: new Date().toISOString(), files };
  await mkdir(dirname(resolve(directory, output)), { recursive: true });
  await writeFile(resolve(directory, output), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
}

export async function signIntegrityManifest(directory: string, privateKeyFile: string, input = 'integrity.json'): Promise<IntegrityManifestSignature> {
  const manifest = JSON.parse(await readFile(resolve(directory, input), 'utf8')) as IntegrityManifest;
  const payload = canonical(manifest);
  const key = createPrivateKey(await readFile(privateKeyFile, 'utf8'));
  const signature: IntegrityManifestSignature = { schemaVersion: 1, algorithm: 'sha256', manifestSha256: sha256(payload), signature: sign('sha256', Buffer.from(payload), key).toString('base64'), signedAt: new Date().toISOString() };
  await writeFile(resolve(directory, `${input}.sig`), `${JSON.stringify(signature, null, 2)}\n`, 'utf8');
  return signature;
}

export async function verifyIntegrityManifestSignature(directory: string, publicKeyFile: string, input = 'integrity.json'): Promise<boolean> {
  const manifest = JSON.parse(await readFile(resolve(directory, input), 'utf8')) as IntegrityManifest;
  const signature = JSON.parse(await readFile(resolve(directory, `${input}.sig`), 'utf8')) as IntegrityManifestSignature;
  const payload = canonical(manifest);
  if (signature.schemaVersion !== 1 || signature.algorithm !== 'sha256' || signature.manifestSha256 !== sha256(payload)) return false;
  const key = createPublicKey(await readFile(publicKeyFile, 'utf8'));
  return verify('sha256', Buffer.from(payload), key, Buffer.from(signature.signature, 'base64'));
}

export async function verifyIntegrityManifest(directory: string, input = 'integrity.json'): Promise<{ ok: boolean; mismatches: string[] }> {
  const manifest = JSON.parse(await readFile(resolve(directory, input), 'utf8')) as IntegrityManifest;
  const mismatches: string[] = [];
  for (const item of manifest.files) {
    try { if (await sha256File(resolve(directory, item.path)) !== item.sha256) mismatches.push(item.path); }
    catch { mismatches.push(item.path); }
  }
  return { ok: mismatches.length === 0, mismatches };
}
