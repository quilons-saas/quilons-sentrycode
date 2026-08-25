import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { sha256File } from './integrity.js';

export interface IntegrityManifest {
  schemaVersion: 1;
  generatedAt: string;
  files: Array<{ path: string; sha256: string }>;
}

export async function writeIntegrityManifest(directory: string, output = 'integrity.json'): Promise<IntegrityManifest> {
  const names = (await readdir(directory)).filter((name) => name !== output).sort();
  const files: IntegrityManifest['files'] = [];
  for (const name of names) files.push({ path: basename(name), sha256: await sha256File(resolve(directory, name)) });
  const manifest: IntegrityManifest = { schemaVersion: 1, generatedAt: new Date().toISOString(), files };
  await mkdir(dirname(resolve(directory, output)), { recursive: true });
  await writeFile(resolve(directory, output), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
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
