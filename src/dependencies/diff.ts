import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { DependencyChange, DependencyComponent, DependencySnapshot } from '../core/types.js';
import { compareVersions } from './versions.js';
import { parseDependencyFiles } from './discover.js';

const execFileAsync = promisify(execFile);
const TRACKED = ['package-lock.json', 'requirements.txt', 'pyproject.toml'];

function key(component: DependencyComponent): string { return `${component.ecosystem}:${component.name.toLowerCase()}`; }

export function diffDependencies(before: DependencySnapshot, after: DependencySnapshot): DependencyChange[] {
  const beforeMap = new Map(before.components.map((item) => [key(item), item]));
  const afterMap = new Map(after.components.map((item) => [key(item), item]));
  const keys = new Set([...beforeMap.keys(), ...afterMap.keys()]);
  const changes: DependencyChange[] = [];
  for (const itemKey of [...keys].sort()) {
    const oldValue = beforeMap.get(itemKey);
    const newValue = afterMap.get(itemKey);
    if (!oldValue && newValue) changes.push({ kind: 'added', ecosystem: newValue.ecosystem, name: newValue.name, after: newValue });
    else if (oldValue && !newValue) changes.push({ kind: 'removed', ecosystem: oldValue.ecosystem, name: oldValue.name, before: oldValue });
    else if (oldValue && newValue && oldValue.version !== newValue.version) {
      const comparison = compareVersions(newValue.version, oldValue.version);
      changes.push({ kind: comparison > 0 ? 'upgraded' : comparison < 0 ? 'downgraded' : 'changed', ecosystem: newValue.ecosystem, name: newValue.name, before: oldValue, after: newValue });
    }
  }
  return changes;
}

async function gitShow(root: string, ref: string, path: string): Promise<string | undefined> {
  try { return (await execFileAsync('git', ['-C', root, 'show', `${ref}:${path}`], { encoding: 'utf8', maxBuffer: 20_000_000 })).stdout; }
  catch { return undefined; }
}

export async function dependencySnapshotAtRef(root: string, ref: string, generatedAt = new Date().toISOString()): Promise<DependencySnapshot> {
  const files: Record<string, string> = {};
  for (const name of TRACKED) {
    const content = await gitShow(root, ref, name);
    if (content !== undefined) files[name] = content;
  }
  return parseDependencyFiles(files, generatedAt);
}
