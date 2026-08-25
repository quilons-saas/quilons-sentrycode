import { readdir, readFile } from 'node:fs/promises';
import { extname, join, relative, resolve } from 'node:path';
import type { AutomotiveImportDocument, AutomotiveImportedFinding, AutomotiveStandard } from './types.js';

const STANDARDS = new Set<AutomotiveStandard>(['misra-c', 'misra-cpp', 'autosar-cpp']);

function severity(value: unknown): AutomotiveImportedFinding['severity'] {
  if (['info','low','medium','high','critical','error','warning','note'].includes(String(value))) return value as AutomotiveImportedFinding['severity'];
  return undefined;
}

function parseNative(raw: unknown, path: string): AutomotiveImportDocument {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`Automotive import ${path} must be an object`);
  const obj = raw as Record<string, unknown>;
  if (obj.schemaVersion !== 1 || !STANDARDS.has(obj.standard as AutomotiveStandard)) throw new Error(`Automotive import ${path} has unsupported schemaVersion or standard`);
  if (!obj.tool || typeof obj.tool !== 'object' || Array.isArray(obj.tool)) throw new Error(`Automotive import ${path} requires tool metadata`);
  const tool = obj.tool as Record<string, unknown>;
  if (typeof tool.name !== 'string' || !tool.name.trim()) throw new Error(`Automotive import ${path} requires tool.name`);
  if (!Array.isArray(obj.findings)) throw new Error(`Automotive import ${path} requires findings[]`);
  const findings = obj.findings.map((value, index) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Automotive import ${path} findings[${index}] must be an object`);
    const item = value as Record<string, unknown>;
    if (typeof item.ruleId !== 'string' || typeof item.message !== 'string') throw new Error(`Automotive import ${path} findings[${index}] requires ruleId and message`);
    const normalizedSeverity = severity(item.severity);
    return {
      ruleId: item.ruleId,
      message: item.message,
      ...(normalizedSeverity ? { severity: normalizedSeverity } : {}),
      ...(typeof item.path === 'string' ? { path: item.path } : {}),
      ...(typeof item.line === 'number' ? { line: item.line } : {}),
      ...(typeof item.column === 'number' ? { column: item.column } : {}),
      ...(Array.isArray(item.tags) && item.tags.every((tag) => typeof tag === 'string') ? { tags: item.tags as string[] } : {}),
      ...(typeof item.fingerprint === 'string' ? { fingerprint: item.fingerprint } : {})
    } satisfies AutomotiveImportedFinding;
  });
  return { schemaVersion: 1, standard: obj.standard as AutomotiveStandard, tool: { name: tool.name, ...(typeof tool.version === 'string' ? { version: tool.version } : {}) }, ...(typeof obj.generatedAt === 'string' ? { generatedAt: obj.generatedAt } : {}), findings };
}

function standardFromSarif(run: Record<string, unknown>, fallback?: AutomotiveStandard): AutomotiveStandard {
  const properties = (run.properties && typeof run.properties === 'object' && !Array.isArray(run.properties)) ? run.properties as Record<string, unknown> : {};
  const value = properties.automotiveStandard ?? fallback;
  if (!STANDARDS.has(value as AutomotiveStandard)) throw new Error('SARIF automotive import requires run.properties.automotiveStandard');
  return value as AutomotiveStandard;
}

function parseSarif(raw: unknown, path: string): AutomotiveImportDocument[] {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`SARIF import ${path} must be an object`);
  const doc = raw as Record<string, unknown>;
  if (!Array.isArray(doc.runs)) throw new Error(`SARIF import ${path} requires runs[]`);
  return doc.runs.map((value, runIndex) => {
    const run = value as Record<string, unknown>;
    const standard = standardFromSarif(run);
    const driver = (((run.tool as Record<string, unknown> | undefined)?.driver ?? {}) as Record<string, unknown>);
    const toolName = typeof driver.name === 'string' ? driver.name : 'sarif-tool';
    const results = Array.isArray(run.results) ? run.results : [];
    const findings = results.map((resultValue, resultIndex) => {
      const result = resultValue as Record<string, unknown>;
      if (typeof result.ruleId !== 'string') throw new Error(`SARIF ${path} run ${runIndex} result ${resultIndex} requires ruleId`);
      const messageObj = (result.message && typeof result.message === 'object') ? result.message as Record<string, unknown> : {};
      const location = Array.isArray(result.locations) ? result.locations[0] as Record<string, unknown> | undefined : undefined;
      const physical = location?.physicalLocation as Record<string, unknown> | undefined;
      const artifact = physical?.artifactLocation as Record<string, unknown> | undefined;
      const region = physical?.region as Record<string, unknown> | undefined;
      const level = result.level === 'error' ? 'error' : result.level === 'warning' ? 'warning' : 'note';
      return {
        ruleId: result.ruleId,
        message: typeof messageObj.text === 'string' ? messageObj.text : `Automotive rule ${result.ruleId}`,
        severity: level,
        ...(typeof artifact?.uri === 'string' ? { path: artifact.uri } : {}),
        ...(typeof region?.startLine === 'number' ? { line: region.startLine } : {}),
        ...(typeof region?.startColumn === 'number' ? { column: region.startColumn } : {})
      } satisfies AutomotiveImportedFinding;
    });
    return { schemaVersion: 1, standard, tool: { name: toolName, ...(typeof driver.version === 'string' ? { version: driver.version } : {}) }, findings };
  });
}

async function walk(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    const nested = await Promise.all(entries.map(async (entry) => entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)]));
    return nested.flat().filter((file) => extname(file).toLowerCase() === '.json');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

export async function loadAutomotiveImports(root: string, directory: string): Promise<Array<{ source: string; document: AutomotiveImportDocument }>> {
  const dir = resolve(root, directory);
  const files = await walk(dir);
  const output: Array<{ source: string; document: AutomotiveImportDocument }> = [];
  for (const file of files.sort()) {
    const raw = JSON.parse(await readFile(file, 'utf8')) as unknown;
    if (raw && typeof raw === 'object' && !Array.isArray(raw) && (raw as Record<string, unknown>).version === '2.1.0') {
      for (const document of parseSarif(raw, file)) output.push({ source: relative(root, file).replaceAll('\\', '/'), document });
    } else output.push({ source: relative(root, file).replaceAll('\\', '/'), document: parseNative(raw, file) });
  }
  return output;
}
