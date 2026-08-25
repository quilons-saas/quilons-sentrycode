import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export interface IncrementalCache {
  schemaVersion: 1;
  repository: string;
  lastSuccessfulCommit: string;
  updatedAt: string;
}

export async function readIncrementalCache(root: string, file: string): Promise<IncrementalCache | null> {
  try {
    const parsed = JSON.parse(await readFile(resolve(root, file), 'utf8')) as IncrementalCache;
    return parsed.schemaVersion === 1 ? parsed : null;
  } catch { return null; }
}

export async function writeIncrementalCache(root: string, file: string, cache: IncrementalCache): Promise<void> {
  const path = resolve(root, file);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(cache, null, 2)}\n`, 'utf8');
}
