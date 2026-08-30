import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { DependencyComponent, Severity, SentryCodeConfig, VulnerabilityAdvisory } from '../core/types.js';
import { discoverDependencies } from '../dependencies/discover.js';
import { enrichDependencyMetadata } from '../dependencies/metadata.js';

interface OsvQueryResult { vulns?: Array<{ id: string; modified?: string }>; next_page_token?: string; }
interface OsvBatch { results?: OsvQueryResult[]; }

function ecosystem(value: DependencyComponent['ecosystem']): string | undefined { return value === 'npm' ? 'npm' : value === 'pypi' ? 'PyPI' : value === 'maven' ? 'Maven' : value === 'nuget' ? 'NuGet' : value === 'cargo' ? 'crates.io' : value === 'go' ? 'Go' : undefined; }
function severityFrom(value: Record<string, unknown>): Severity {
  const database = value.database_specific && typeof value.database_specific === 'object' ? value.database_specific as Record<string, unknown> : {};
  const raw = String(database.severity ?? '').toLowerCase();
  if (raw.includes('critical')) return 'critical'; if (raw.includes('high')) return 'high'; if (raw.includes('moderate') || raw.includes('medium')) return 'medium'; if (raw.includes('low')) return 'low';
  return 'medium';
}
function fixedVersion(value: Record<string, unknown>): string | undefined {
  const affected = Array.isArray(value.affected) ? value.affected : [];
  for (const entryValue of affected) {
    if (!entryValue || typeof entryValue !== 'object' || Array.isArray(entryValue)) continue;
    const ranges = Array.isArray((entryValue as Record<string, unknown>).ranges) ? (entryValue as Record<string, unknown>).ranges as unknown[] : [];
    for (const rangeValue of ranges) {
      if (!rangeValue || typeof rangeValue !== 'object' || Array.isArray(rangeValue)) continue;
      const events = Array.isArray((rangeValue as Record<string, unknown>).events) ? (rangeValue as Record<string, unknown>).events as unknown[] : [];
      for (const eventValue of events) if (eventValue && typeof eventValue === 'object' && !Array.isArray(eventValue) && typeof (eventValue as Record<string, unknown>).fixed === 'string') return (eventValue as Record<string, unknown>).fixed as string;
    }
  }
  return undefined;
}

async function jsonFetch(url: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { const response = await fetch(url, { ...init, signal: controller.signal }); if (!response.ok) throw new Error(`OSV request failed: HTTP ${response.status}`); return await response.json(); }
  finally { clearTimeout(timer); }
}

export async function syncOsvDatabase(root: string, config: SentryCodeConfig, serviceRoot = ''): Promise<{ advisoryCount: number; componentCount: number; updatedAt: string }> {
  if (config.offline.enabled) throw new Error('OSV synchronization is unavailable in offline mode');
  if (!config.vulnerabilities.osv.enabled) throw new Error('OSV synchronization is disabled by configuration');
  const snapshot = await discoverDependencies(root, new Date().toISOString(), serviceRoot);
  const components = await enrichDependencyMetadata(root, snapshot.components, { serviceRoot, offline: false });
  const supported = components.flatMap((item) => { const mapped=ecosystem(item.ecosystem); return mapped ? [{ component:item, ecosystem:mapped }] : []; });
  const queries = supported.map(({component,ecosystem: mapped}) => ({ package: { name: component.name, ecosystem: mapped }, version: component.version }));
  const endpoint = config.vulnerabilities.osv.endpoint.replace(/\/$/, '');
  const batch = queries.length ? await jsonFetch(`${endpoint}/v1/querybatch`, { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'quilons-sentrycode' }, body: JSON.stringify({ queries }) }, config.vulnerabilities.osv.timeoutMs) as OsvBatch : {results:[]};
  const advisories: VulnerabilityAdvisory[] = [];
  for (let i = 0; i < supported.length; i += 1) {
    const component = supported[i]!.component; const ids = batch.results?.[i]?.vulns ?? [];
    for (const item of ids) {
      const detail = await jsonFetch(`${endpoint}/v1/vulns/${encodeURIComponent(item.id)}`, { headers: { 'user-agent': 'quilons-sentrycode' } }, config.vulnerabilities.osv.timeoutMs) as Record<string, unknown>;
      const fixed = fixedVersion(detail);
      advisories.push({ id: item.id, ecosystem: component.ecosystem, package: component.name, affected: `=${component.version}`, severity: severityFrom(detail), title: typeof detail.summary === 'string' ? detail.summary : item.id, ...(fixed ? { fixedVersion: fixed } : {}), source: 'OSV.dev', url: `https://osv.dev/vulnerability/${encodeURIComponent(item.id)}` });
    }
  }
  const unique = [...new Map(advisories.map((item) => [`${item.id}|${item.ecosystem}|${item.package}|${item.affected}`, item])).values()];
  const updatedAt = new Date().toISOString();
  const target = resolve(root, config.vulnerabilities.databaseFile); await mkdir(dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify({ schemaVersion: 1, updatedAt, advisories: unique }, null, 2)}\n`, 'utf8');
  return { advisoryCount: unique.length, componentCount: supported.length, updatedAt };
}
