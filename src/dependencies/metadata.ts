import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { DependencyComponent } from '../core/types.js';

interface PackageMetadata { license?: string; }
async function json(path: string): Promise<Record<string, unknown> | null> {
  try { return JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>; } catch { return null; }
}

function npmPackagePath(root: string, serviceRoot: string, component: DependencyComponent): string {
  const packagePath = component.packagePath?.replace(/\\/g, '/') ?? `node_modules/${component.name}`;
  return resolve(root, serviceRoot, packagePath, 'package.json');
}

/** Enrich package metadata from locally installed package manifests. No source code or package data leaves the machine. */
export async function enrichDependencyMetadata(root: string, components: DependencyComponent[], options: { serviceRoot?: string; offline?: boolean } = {}): Promise<DependencyComponent[]> {
  const serviceRoot = options.serviceRoot ?? '';
  const result: DependencyComponent[] = [];
  for (const component of components) {
    if (component.license || component.ecosystem !== 'npm') { result.push(component); continue; }
    const manifest = await json(npmPackagePath(root, serviceRoot, component));
    const license = typeof manifest?.license === 'string' ? manifest.license : undefined;
    result.push(license ? { ...component, license } : component);
  }
  return result;
}
