import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { DependencyComponent, VulnerabilityAdvisory } from '../core/types.js';
import { satisfiesSimpleRange } from '../dependencies/versions.js';

interface VulnerabilityDatabaseFile {
  schemaVersion: 1;
  updatedAt?: string;
  advisories: VulnerabilityAdvisory[];
}

export async function loadVulnerabilityDatabase(root: string, path: string): Promise<{ advisories: VulnerabilityAdvisory[]; updatedAt?: string; available: boolean }> {
  const absolute = resolve(root, path);
  try {
    const parsed = JSON.parse(await readFile(absolute, 'utf8')) as VulnerabilityDatabaseFile;
    if (parsed.schemaVersion !== 1 || !Array.isArray(parsed.advisories)) throw new Error('Unsupported vulnerability DB schema');
    return { advisories: parsed.advisories, ...(parsed.updatedAt ? { updatedAt: parsed.updatedAt } : {}), available: true };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { advisories: [], available: false };
    throw error;
  }
}

export function vulnerabilitiesFor(component: DependencyComponent, advisories: VulnerabilityAdvisory[]): VulnerabilityAdvisory[] {
  return advisories.filter((item) => item.ecosystem === component.ecosystem && item.package.toLowerCase() === component.name.toLowerCase() && satisfiesSimpleRange(component.version, item.affected));
}
