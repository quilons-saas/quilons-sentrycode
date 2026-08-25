import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createPublicKey, verify } from 'node:crypto';
import { sha256 } from '../utils/hash.js';
import type { VulnerabilityAdvisory } from '../core/types.js';

export interface VulnerabilityBundle {
  schemaVersion: 1;
  id: string;
  version: string;
  createdAt: string;
  database: { schemaVersion: 1; updatedAt: string; advisories: VulnerabilityAdvisory[] };
  databaseSha256: string;
  signature?: string;
}

function canonicalDatabase(bundle: VulnerabilityBundle): string { return JSON.stringify(bundle.database); }

export function validateBundle(bundle: VulnerabilityBundle): void {
  if (bundle.schemaVersion !== 1 || bundle.database?.schemaVersion !== 1 || !Array.isArray(bundle.database?.advisories)) throw new Error('Unsupported vulnerability intelligence bundle');
  if (sha256(canonicalDatabase(bundle)) !== bundle.databaseSha256) throw new Error('Vulnerability intelligence bundle digest mismatch');
}

export async function importVulnerabilityBundle(root: string, bundleFile: string, targetFile: string, options: { requireSignature: boolean; publicKeyFile?: string }): Promise<{ id: string; version: string; advisoryCount: number; updatedAt: string }> {
  const bundle = JSON.parse(await readFile(resolve(root, bundleFile), 'utf8')) as VulnerabilityBundle;
  validateBundle(bundle);
  if (options.requireSignature) {
    if (!bundle.signature || !options.publicKeyFile) throw new Error('Signed vulnerability intelligence bundle and public key are required');
    const key = createPublicKey(await readFile(resolve(root, options.publicKeyFile), 'utf8'));
    if (!verify('sha256', Buffer.from(canonicalDatabase(bundle)), key, Buffer.from(bundle.signature, 'base64'))) throw new Error('Vulnerability intelligence bundle signature verification failed');
  }
  const target = resolve(root, targetFile);
  await mkdir(dirname(target), { recursive: true });
  const tmp = `${target}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(bundle.database, null, 2)}\n`, 'utf8');
  await rename(tmp, target);
  return { id: bundle.id, version: bundle.version, advisoryCount: bundle.database.advisories.length, updatedAt: bundle.database.updatedAt };
}
