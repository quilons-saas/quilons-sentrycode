import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SCHEMA_VERSION, type Finding, type ScannerContext, type ScannerPlugin, type ScannerResult, type Severity } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';

function severity(level: unknown): Severity {
  if (level === 'error') return 'high';
  if (level === 'warning') return 'medium';
  if (level === 'note') return 'low';
  return 'medium';
}

async function runCommand(root: string, command: string, args: string[], timeoutMs: number): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer | string) => { stderr += chunk.toString(); if (stderr.length > 65536) stderr = stderr.slice(-65536); });
    const timer = setTimeout(() => { child.kill(); reject(new Error(`external SAST command timed out after ${timeoutMs}ms`)); }, timeoutMs);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('close', (code) => {
      clearTimeout(timer);
      // Many scanners use non-zero to mean findings; SARIF remains the source of truth.
      if (code === null) reject(new Error('external SAST command terminated without an exit code'));
      else if (code > 2) reject(new Error(`external SAST command failed with exit code ${code}: ${stderr.trim()}`));
      else resolvePromise();
    });
  });
}

export function findingsFromSarif(raw: unknown, detectedAt: string): { findings: Finding[]; toolNames: string[] } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('External SAST SARIF must be an object');
  const doc = raw as Record<string, unknown>;
  if (doc.version !== '2.1.0' || !Array.isArray(doc.runs)) throw new Error('External SAST input must be SARIF 2.1.0');
  const findings: Finding[] = [];
  const toolNames: string[] = [];
  for (const [runIndex, runValue] of doc.runs.entries()) {
    if (!runValue || typeof runValue !== 'object' || Array.isArray(runValue)) continue;
    const run = runValue as Record<string, unknown>;
    const driver = ((run.tool as Record<string, unknown> | undefined)?.driver ?? {}) as Record<string, unknown>;
    const tool = typeof driver.name === 'string' ? driver.name : `sarif-tool-${runIndex + 1}`;
    toolNames.push(tool);
    const results = Array.isArray(run.results) ? run.results : [];
    for (const [index, resultValue] of results.entries()) {
      if (!resultValue || typeof resultValue !== 'object' || Array.isArray(resultValue)) continue;
      const result = resultValue as Record<string, unknown>;
      const ruleId = typeof result.ruleId === 'string' ? result.ruleId : `external-rule-${index + 1}`;
      const messageObj = result.message && typeof result.message === 'object' && !Array.isArray(result.message) ? result.message as Record<string, unknown> : {};
      const message = typeof messageObj.text === 'string' ? messageObj.text : `External SAST finding ${ruleId}`;
      const location = Array.isArray(result.locations) ? result.locations[0] as Record<string, unknown> | undefined : undefined;
      const physical = location?.physicalLocation as Record<string, unknown> | undefined;
      const artifact = physical?.artifactLocation as Record<string, unknown> | undefined;
      const region = physical?.region as Record<string, unknown> | undefined;
      const path = typeof artifact?.uri === 'string' ? decodeURIComponent(artifact.uri.replace(/^file:\/\//, '')).replaceAll('\\', '/') : undefined;
      const line = typeof region?.startLine === 'number' ? region.startLine : undefined;
      const column = typeof region?.startColumn === 'number' ? region.startColumn : undefined;
      const fp = stableId('fp', `external-sast|${tool}|${ruleId}|${path ?? ''}|${line ?? 0}|${message}`);
      findings.push({
        schemaVersion: SCHEMA_VERSION,
        id: stableId('finding', `${fp}|${detectedAt}`),
        type: 'sast', scanner: 'external-sast', ruleId,
        title: `${tool}: ${ruleId}`, description: message, severity: severity(result.level), fingerprint: fp, detectedAt,
        ...(path ? { location: { path, ...(line ? { line } : {}), ...(column ? { column } : {}) } } : {}),
        remediation: 'Review the external analyzer guidance and remediate or create an approved, time-bounded waiver.',
        metadata: { tool, sarifRun: runIndex }
      });
    }
  }
  return { findings: [...new Map(findings.map((item) => [item.fingerprint, item])).values()], toolNames: [...new Set(toolNames)] };
}

export class ExternalSastScanner implements ScannerPlugin {
  readonly id = 'external-sast';
  readonly version = '0.1.0';
  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now();
    const at = context.now().toISOString();
    const cfg = context.config.sast.external;
    if (!cfg.enabled) return { scanner: this.id, findings: [], evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped', error: 'external SAST disabled by configuration' };
    if (cfg.command) await runCommand(context.repository.root, cfg.command, cfg.args, cfg.timeoutMs);
    const sarifPath = resolve(context.repository.root, cfg.sarifFile);
    const parsed = findingsFromSarif(JSON.parse(await readFile(sarifPath, 'utf8')) as unknown, at);
    return {
      scanner: this.id,
      findings: parsed.findings,
      evidence: [{ schemaVersion: SCHEMA_VERSION, id: stableId('evidence', `${context.repository.commitSha}|external-sast|${at}`), type: 'sast.scan', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch, generatedAt: at, findingIds: parsed.findings.map((item) => item.id), metadata: { scannerVersion: this.version, toolCount: parsed.toolNames.length, tools: parsed.toolNames.join(','), findingCount: parsed.findings.length, sarifFile: cfg.sarifFile } }],
      durationMs: Math.round(performance.now() - started)
    };
  }
}
