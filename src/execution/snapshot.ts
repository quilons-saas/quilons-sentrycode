import { lstat, readFile, realpath, stat } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import type { RunnerInputFile, RunnerInputPayload } from './contracts.js';
import { sha256 } from './contracts.js';
import { discoverFiles } from '../core/files.js';
import type { SentryCodeConfig } from '../core/types.js';

export interface SnapshotLimits {
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
}

export const DEFAULT_SNAPSHOT_LIMITS: SnapshotLimits = {
  maxFiles: 10_000,
  maxTotalBytes: 256 * 1024 * 1024,
  maxFileBytes: 16 * 1024 * 1024
};

function safeRelative(root: string, absolute: string): string {
  const rel = relative(root, absolute).replace(/\\/g, '/');
  if (!rel || rel === '.' || rel.startsWith('../') || rel.includes('/../') || rel.startsWith('/') || rel.includes('\0')) {
    throw new Error(`Unsafe snapshot path: ${rel || '<root>'}`);
  }
  return rel;
}

export function canonicalInputDigest(files: Array<Pick<RunnerInputFile, 'path' | 'size' | 'sha256'>>): string {
  const canonical = [...files]
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((file) => `${file.path}\0${file.size}\0${file.sha256}\0`)
    .join('');
  return sha256(canonical);
}

export async function snapshotRepository(
  root: string,
  config: SentryCodeConfig,
  limits: SnapshotLimits = DEFAULT_SNAPSHOT_LIMITS
): Promise<RunnerInputPayload> {
  const rootReal = await realpath(resolve(root));
  const discovered = await discoverFiles(rootReal, config);
  if (discovered.length > limits.maxFiles) throw new Error(`Repository snapshot exceeds file limit (${limits.maxFiles})`);

  const files: RunnerInputFile[] = [];
  let totalBytes = 0;
  for (const absolute of discovered) {
    const before = await lstat(absolute);
    if (!before.isFile() || before.isSymbolicLink()) throw new Error(`Snapshot input is not a regular file: ${safeRelative(rootReal, absolute)}`);
    const resolved = await realpath(absolute);
    const relCheck = relative(rootReal, resolved);
    if (relCheck === '..' || relCheck.startsWith(`..${sep}`) || resolve(resolved) === rootReal) throw new Error(`Snapshot input escapes repository: ${absolute}`);
    const path = safeRelative(rootReal, resolved);
    if (before.size > Math.min(limits.maxFileBytes, config.scan.maxFileBytes)) throw new Error(`Snapshot file exceeds limit: ${path}`);
    const content = await readFile(resolved);
    const after = await stat(resolved);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || (before.ino && after.ino && before.ino !== after.ino)) {
      throw new Error(`Snapshot source changed while reading: ${path}`);
    }
    totalBytes += content.length;
    if (totalBytes > limits.maxTotalBytes) throw new Error(`Repository snapshot exceeds byte limit (${limits.maxTotalBytes})`);
    files.push({ path, size: content.length, sha256: sha256(content), contentBase64: content.toString('base64') });
  }

  files.sort((a, b) => a.path.localeCompare(b.path));
  return { digest: canonicalInputDigest(files), files, totalBytes };
}
