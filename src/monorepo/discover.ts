import { readFile, readdir } from 'node:fs/promises';
import { basename, dirname, relative, resolve } from 'node:path';
import type { SentryCodeConfig, ServiceComponent } from '../core/types.js';

async function exists(path: string): Promise<boolean> {
  try { await readFile(path); return true; } catch { return false; }
}

function normalize(root: string, path: string): string {
  return relative(root, resolve(root, path)).replace(/\\/g,'/').replace(/^\.$/, '');
}

async function npmWorkspaceRoots(root: string): Promise<string[]> {
  try {
    const pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')) as { workspaces?: string[] | { packages?: string[] } };
    const patterns = Array.isArray(pkg.workspaces) ? pkg.workspaces : pkg.workspaces?.packages ?? [];
    const roots: string[] = [];
    for (const pattern of patterns) {
      if (!pattern.endsWith('/*')) continue;
      const parent = resolve(root, pattern.slice(0, -2));
      try {
        for (const entry of await readdir(parent, { withFileTypes: true })) if (entry.isDirectory()) roots.push(relative(root, resolve(parent, entry.name)).replace(/\\/g,'/'));
      } catch {}
    }
    return roots;
  } catch { return []; }
}

export async function discoverServices(root: string, config: SentryCodeConfig): Promise<ServiceComponent[]> {
  if (!config.monorepo.enabled) return [{ name: basename(root), root: '', kind: 'generic' }];
  const roots = new Set(config.monorepo.serviceRoots.map((x) => normalize(root, x)));
  if (config.monorepo.discoverWorkspaces) for (const x of await npmWorkspaceRoots(root)) roots.add(x);
  if (!roots.size) roots.add('');
  const services: ServiceComponent[] = [];
  for (const serviceRoot of [...roots].sort()) {
    const abs = resolve(root, serviceRoot || '.');
    let kind: ServiceComponent['kind'] = 'generic';
    if (await exists(resolve(abs, 'package.json'))) kind = 'node';
    else if (await exists(resolve(abs, 'pyproject.toml')) || await exists(resolve(abs, 'requirements.txt'))) kind = 'python';
    services.push({ name: serviceRoot ? basename(serviceRoot) : basename(root), root: serviceRoot, kind });
  }
  return services;
}

export function affectedServices(changedFiles: string[], services: ServiceComponent[]): ServiceComponent[] {
  if (!changedFiles.length) return [];
  const global = changedFiles.some((f) => !services.some((s) => s.root && (f === s.root || f.startsWith(`${s.root}/`))));
  if (global) return services;
  return services.filter((s) => !s.root || changedFiles.some((f) => f === s.root || f.startsWith(`${s.root}/`)));
}
