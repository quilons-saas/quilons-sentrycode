import { readdir, stat } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { matchesAny } from '../utils/glob.js';
import type { SentryCodeConfig } from './types.js';

export async function discoverFiles(root: string, config: SentryCodeConfig): Promise<string[]> {
  const files: string[] = [];

  async function walk(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = resolve(directory, entry.name);
      const rel = relative(root, absolute).replace(/\\/g, '/');
      const relForDir = entry.isDirectory() ? `${rel}/` : rel;
      if (matchesAny(relForDir, config.scan.exclude) || matchesAny(rel, config.scan.exclude)) continue;
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile()) {
        if (!matchesAny(rel, config.scan.include)) continue;
        const fileStat = await stat(absolute);
        if (fileStat.size <= config.scan.maxFileBytes) files.push(absolute);
      }
    }
  }

  await walk(root);
  return files.sort();
}
