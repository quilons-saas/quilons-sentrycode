import { readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type { DependencyComponent, DependencySnapshot } from '../core/types.js';

interface PackageLock {
  packages?: Record<string, { name?: string; version?: string; dev?: boolean; resolved?: string; license?: string }>;
  dependencies?: Record<string, { version?: string; dev?: boolean; resolved?: string }>;
}

function npmPurl(name: string, version: string): string {
  return `pkg:npm/${encodeURIComponent(name).replace('%40', '@')}@${encodeURIComponent(version)}`;
}

function pypiPurl(name: string, version: string): string {
  return `pkg:pypi/${encodeURIComponent(name.toLowerCase())}@${encodeURIComponent(version)}`;
}

async function exists(path: string): Promise<boolean> {
  try { await readFile(path); return true; } catch { return false; }
}

function parsePackageLock(content: string): DependencyComponent[] {
  const lock = JSON.parse(content) as PackageLock;
  const components: DependencyComponent[] = [];
  if (lock.packages) {
    for (const [packagePath, entry] of Object.entries(lock.packages)) {
      if (!packagePath || !entry.version) continue;
      const pathName = packagePath.split('node_modules/').at(-1);
      const name = entry.name ?? pathName;
      if (!name) continue;
      components.push({ ecosystem: 'npm', name, version: entry.version, direct: packagePath.startsWith('node_modules/') && !packagePath.slice('node_modules/'.length).includes('/node_modules/'), dev: Boolean(entry.dev), source: entry.resolved ?? 'package-lock.json', purl: npmPurl(name, entry.version), packagePath, ...(entry.license ? { license: entry.license } : {}) });
    }
  } else if (lock.dependencies) {
    for (const [name, entry] of Object.entries(lock.dependencies)) {
      if (!entry.version) continue;
      components.push({ ecosystem: 'npm', name, version: entry.version, direct: true, dev: Boolean(entry.dev), source: entry.resolved ?? 'package-lock.json', purl: npmPurl(name, entry.version) });
    }
  }
  return components;
}

function parseRequirements(content: string, source: string): DependencyComponent[] {
  const components: DependencyComponent[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const withoutMarker = line.split(';')[0]!.trim();
    const match = withoutMarker.match(/^([A-Za-z0-9_.-]+)\s*==\s*([^\s]+)$/);
    if (!match) continue;
    const [, name, version] = match;
    components.push({ ecosystem: 'pypi', name: name!, version: version!, direct: true, dev: false, source, purl: pypiPurl(name!, version!) });
  }
  return components;
}

function parsePyproject(content: string): DependencyComponent[] {
  const components: DependencyComponent[] = [];
  let inDependencies = false;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === 'dependencies = [' || line.startsWith('dependencies=[')) { inDependencies = true; continue; }
    if (inDependencies && line.startsWith(']')) { inDependencies = false; continue; }
    if (!inDependencies) continue;
    const quoted = line.match(/["']([^"']+)["']/)?.[1];
    if (!quoted) continue;
    const match = quoted.match(/^([A-Za-z0-9_.-]+)\s*==\s*([^\s;]+)$/);
    if (!match) continue;
    components.push({ ecosystem: 'pypi', name: match[1]!, version: match[2]!, direct: true, dev: false, source: 'pyproject.toml', purl: pypiPurl(match[1]!, match[2]!) });
  }
  return components;
}

export function parseDependencyFiles(files: Record<string, string>, generatedAt: string): DependencySnapshot {
  const components: DependencyComponent[] = [];
  if (files['package-lock.json']) components.push(...parsePackageLock(files['package-lock.json']));
  if (files['requirements.txt']) components.push(...parseRequirements(files['requirements.txt'], 'requirements.txt'));
  if (files['pyproject.toml']) components.push(...parsePyproject(files['pyproject.toml']));
  const unique = [...new Map(components.map((item) => [`${item.ecosystem}:${item.name.toLowerCase()}:${item.version}`, item])).values()];
  unique.sort((a, b) => `${a.ecosystem}:${a.name}:${a.version}`.localeCompare(`${b.ecosystem}:${b.name}:${b.version}`));
  return { generatedAt, components: unique };
}

export async function discoverDependencies(root: string, generatedAt = new Date().toISOString()): Promise<DependencySnapshot> {
  const files: Record<string, string> = {};
  for (const name of ['package-lock.json', 'requirements.txt', 'pyproject.toml']) {
    const path = join(root, name);
    if (await exists(path)) files[name] = await readFile(path, 'utf8');
  }
  return parseDependencyFiles(files, generatedAt);
}
