import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type {
  PolicyContext,
  PolicyDocument,
  PolicyField,
  PolicyLevel,
  ScannerFailureMode,
  Severity
} from '../core/types.js';

const LEVELS: PolicyLevel[] = ['organization', 'tenant', 'project', 'repository', 'service'];
const FIELDS: PolicyField[] = ['failOn', 'warnOn', 'requiredScanners', 'scannerFailureModes'];
const SEVERITIES = new Set<Severity>(['info', 'low', 'medium', 'high', 'critical']);
const FAILURE_MODES = new Set<ScannerFailureMode>(['fail', 'warn', 'ignore']);

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function severityArray(value: unknown, label: string): Severity[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || !SEVERITIES.has(v as Severity))) {
    throw new Error(`${label} must contain valid severities`);
  }
  return value as Severity[];
}

function stringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || !v.trim())) throw new Error(`${label} must be an array of non-empty strings`);
  return value as string[];
}

function failureModes(value: unknown, label: string): Record<string, ScannerFailureMode> | undefined {
  if (value === undefined) return undefined;
  const raw = object(value, label);
  const result: Record<string, ScannerFailureMode> = {};
  for (const [scanner, mode] of Object.entries(raw)) {
    if (typeof mode !== 'string' || !FAILURE_MODES.has(mode as ScannerFailureMode)) throw new Error(`${label}.${scanner} must be fail, warn, or ignore`);
    result[scanner] = mode as ScannerFailureMode;
  }
  return result;
}

function parseDate(value: unknown, label: string): string | undefined {
  const text = optionalString(value, label);
  if (text === undefined) return undefined;
  if (Number.isNaN(new Date(text).getTime())) throw new Error(`${label} must be a valid timestamp`);
  return text;
}

export function parsePolicyDocument(raw: unknown, path: string): PolicyDocument {
  const value = object(raw, `policy ${path}`);
  if (value.schemaVersion !== 1) throw new Error(`policy ${path} requires schemaVersion 1`);
  if (typeof value.id !== 'string' || !value.id.trim()) throw new Error(`policy ${path} requires id`);
  if (typeof value.version !== 'string' || !value.version.trim()) throw new Error(`policy ${path} requires version`);
  if (typeof value.level !== 'string' || !LEVELS.includes(value.level as PolicyLevel)) throw new Error(`policy ${path} has invalid level`);

  const scopeRaw = value.scope === undefined ? undefined : object(value.scope, `policy ${path}.scope`);
  const enforcementRaw = value.enforcement === undefined ? undefined : object(value.enforcement, `policy ${path}.enforcement`);
  const lock = value.lock === undefined ? undefined : stringArray(value.lock, `policy ${path}.lock`);
  if (lock?.some((field) => !FIELDS.includes(field as PolicyField))) throw new Error(`policy ${path}.lock contains an unsupported field`);

  const tenant = scopeRaw ? optionalString(scopeRaw.tenant, `policy ${path}.scope.tenant`) : undefined;
  const project = scopeRaw ? optionalString(scopeRaw.project, `policy ${path}.scope.project`) : undefined;
  const repository = scopeRaw ? optionalString(scopeRaw.repository, `policy ${path}.scope.repository`) : undefined;
  const service = scopeRaw ? optionalString(scopeRaw.service, `policy ${path}.scope.service`) : undefined;
  const scope = scopeRaw ? {
    ...(tenant ? { tenant } : {}),
    ...(project ? { project } : {}),
    ...(repository ? { repository } : {}),
    ...(service ? { service } : {})
  } : undefined;

  const enforcementFailOn = enforcementRaw ? severityArray(enforcementRaw.failOn, `policy ${path}.enforcement.failOn`) : undefined;
  const enforcementWarnOn = enforcementRaw ? severityArray(enforcementRaw.warnOn, `policy ${path}.enforcement.warnOn`) : undefined;
  const enforcementRequired = enforcementRaw ? stringArray(enforcementRaw.requiredScanners, `policy ${path}.enforcement.requiredScanners`) : undefined;
  const enforcementFailureModes = enforcementRaw ? failureModes(enforcementRaw.scannerFailureModes, `policy ${path}.enforcement.scannerFailureModes`) : undefined;
  const enforcement = enforcementRaw ? {
    ...(enforcementFailOn ? { failOn: enforcementFailOn } : {}),
    ...(enforcementWarnOn ? { warnOn: enforcementWarnOn } : {}),
    ...(enforcementRequired ? { requiredScanners: enforcementRequired } : {}),
    ...(enforcementFailureModes ? { scannerFailureModes: enforcementFailureModes } : {})
  } : undefined;

  const effectiveFrom = parseDate(value.effectiveFrom, `policy ${path}.effectiveFrom`);
  const effectiveUntil = parseDate(value.effectiveUntil, `policy ${path}.effectiveUntil`);

  return {
    schemaVersion: 1,
    id: value.id,
    version: value.version,
    level: value.level as PolicyLevel,
    ...(scope ? { scope } : {}),
    ...(typeof value.description === 'string' ? { description: value.description } : {}),
    ...(effectiveFrom ? { effectiveFrom } : {}),
    ...(effectiveUntil ? { effectiveUntil } : {}),
    ...(enforcement ? { enforcement } : {}),
    ...(lock ? { lock: lock as PolicyField[] } : {})
  };
}

function matchesScope(document: PolicyDocument, context: PolicyContext): boolean {
  const scope = document.scope;
  if (!scope) return true;
  if (scope.tenant !== undefined && scope.tenant !== context.tenant) return false;
  if (scope.project !== undefined && scope.project !== context.project) return false;
  if (scope.repository !== undefined && scope.repository !== context.repository) return false;
  if (scope.service !== undefined && scope.service !== context.service) return false;
  return true;
}

function activeAt(document: PolicyDocument, now: Date): boolean {
  if (document.effectiveFrom && new Date(document.effectiveFrom) > now) return false;
  if (document.effectiveUntil && new Date(document.effectiveUntil) <= now) return false;
  return true;
}

export async function loadPolicyDocuments(root: string, directory: string, context: PolicyContext, now: Date): Promise<Array<{ path: string; document: PolicyDocument }>> {
  const absolute = resolve(root, directory);
  let names: string[];
  try {
    names = (await readdir(absolute)).filter((name: string) => name.endsWith('.json')).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }

  const seen = new Set<string>();
  const result: Array<{ path: string; document: PolicyDocument }> = [];
  for (const name of names) {
    const relative = `${directory.replace(/\\/g, '/')}/${name}`;
    let raw: unknown;
    try {
      raw = JSON.parse(await readFile(resolve(absolute, name), 'utf8')) as unknown;
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error(`Invalid JSON in policy file: ${relative}`);
      throw error;
    }
    const document = parsePolicyDocument(raw, relative);
    const key = `${document.level}:${document.id}`;
    if (seen.has(key)) throw new Error(`Duplicate policy id at level ${document.level}: ${document.id}`);
    seen.add(key);
    if (matchesScope(document, context) && activeAt(document, now)) result.push({ path: relative, document });
  }

  return result.sort((a, b) => LEVELS.indexOf(a.document.level) - LEVELS.indexOf(b.document.level) || a.path.localeCompare(b.path));
}
