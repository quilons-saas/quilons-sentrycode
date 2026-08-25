import { cp, mkdir, readFile, readdir, rm, stat } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

export async function createBackup(root: string, sources: string[], backupDirectory: string): Promise<string> {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const target = resolve(root, backupDirectory, `backup-${stamp}`);
  await mkdir(target, { recursive: true });
  for (const source of sources) {
    const absolute = resolve(root, source);
    try { await stat(absolute); await cp(absolute, resolve(target, basename(source)), { recursive: true, force: false }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  return target;
}

export async function restoreBackup(root: string, backupPath: string, destinations: Record<string, string>): Promise<void> {
  const sourceRoot = resolve(root, backupPath);
  for (const [name, destination] of Object.entries(destinations)) {
    const source = resolve(sourceRoot, name);
    try { await stat(source); await rm(resolve(root, destination), { recursive: true, force: true }); await cp(source, resolve(root, destination), { recursive: true }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
}

export async function applyRetention(root: string, directory: string, retentionDays: number): Promise<string[]> {
  const absolute = resolve(root, directory);
  let names: string[];
  try { names = await readdir(absolute); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
  const cutoff = Date.now() - retentionDays * 86_400_000;
  const removed: string[] = [];
  for (const name of names) {
    const target = resolve(absolute, name);
    const info = await stat(target);
    if (info.mtimeMs < cutoff) { await rm(target, { recursive: true, force: true }); removed.push(name); }
  }
  return removed;
}

export async function applyComplianceRetention(root: string, storeDirectory: string, retentionDays: number): Promise<string[]> {
  const storeRoot = resolve(root, storeDirectory);
  let scopes: string[];
  try { scopes = await readdir(storeRoot); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
  const cutoff = Date.now() - retentionDays * 86_400_000;
  const removed: string[] = [];
  for (const scope of scopes) {
    const runsRoot = resolve(storeRoot, scope, 'runs');
    let runIds: string[];
    try { runIds = await readdir(runsRoot); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
    for (const runId of runIds) {
      const runDir = resolve(runsRoot, runId);
      try {
        const summary = JSON.parse(await readFile(resolve(runDir, 'summary.json'), 'utf8')) as { completedAt?: string };
        const completed = summary.completedAt ? Date.parse(summary.completedAt) : Number.NaN;
        if (Number.isFinite(completed) && completed < cutoff) { await rm(runDir, { recursive: true, force: true }); removed.push(`${scope}/${runId}`); }
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
  }
  return removed;
}
