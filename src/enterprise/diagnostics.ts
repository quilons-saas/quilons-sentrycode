import { access, constants, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { SentryCodeConfig } from '../core/types.js';
import { loadVulnerabilityDatabase } from '../vulnerabilities/database.js';

export interface DiagnosticResult { id: string; ok: boolean; detail: string; }

export async function runDiagnostics(root: string, config: SentryCodeConfig): Promise<DiagnosticResult[]> {
  const checks: DiagnosticResult[] = [];
  const file = async (id: string, path: string, required: boolean) => {
    try { await access(resolve(root, path), constants.R_OK); checks.push({ id, ok: true, detail: 'readable' }); }
    catch { checks.push({ id, ok: !required, detail: required ? 'required file unavailable' : 'optional file unavailable' }); }
  };
  await file('configuration', '.sentrycode/config.json', false);
  await file('vulnerability-database', config.vulnerabilities.databaseFile, config.offline.enabled && config.vulnerabilities.enabled);
  try {
    const db = await loadVulnerabilityDatabase(root, config.vulnerabilities.databaseFile);
    checks.push(db.available
      ? { id: 'vulnerability-database-schema', ok: true, detail: `${db.advisories.length} advisories` }
      : { id: 'vulnerability-database-schema', ok: !config.offline.enabled, detail: 'database absent; schema check skipped' });
  } catch (error) { checks.push({ id: 'vulnerability-database-schema', ok: false, detail: (error as Error).message }); }
  const operationalState = resolve(root, '.sentrycode');
  try {
    await access(operationalState, constants.W_OK);
    checks.push({ id: 'operational-state-write', ok: true, detail: '.sentrycode operational state writable' });
  } catch {
    try {
      await access(root, constants.W_OK);
      checks.push({ id: 'operational-state-write', ok: true, detail: 'repository root can create operational state' });
    } catch {
      checks.push({ id: 'operational-state-write', ok: false, detail: '.sentrycode operational state and repository root are not writable' });
    }
  }
  if (config.integrity.requireSignedConfig) await file('configuration-signature', config.integrity.configSignatureFile, true);
  if (config.integrity.publicKeyFile) await file('integrity-public-key', config.integrity.publicKeyFile, config.integrity.requireSignedConfig);
  try { JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')); checks.push({ id: 'package', ok: true, detail: 'package metadata valid' }); }
  catch { checks.push({ id: 'package', ok: false, detail: 'package metadata unavailable or invalid' }); }
  return checks;
}
