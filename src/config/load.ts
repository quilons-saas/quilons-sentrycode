import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from './defaults.js';
import type { SentryCodeConfig, Severity } from '../core/types.js';

const VALID_SEVERITIES = new Set<Severity>(['info', 'low', 'medium', 'high', 'critical']);

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function mergeConfig(raw: Record<string, unknown>): SentryCodeConfig {
  if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1) {
    throw new Error('Unsupported config schemaVersion; expected 1');
  }
  const scan = raw.scan === undefined ? {} : asObject(raw.scan, 'scan');
  const secrets = raw.secrets === undefined ? {} : asObject(raw.secrets, 'secrets');
  const policy = raw.policy === undefined ? {} : asObject(raw.policy, 'policy');

  const failOn = policy.failOn ?? DEFAULT_CONFIG.policy.failOn;
  const warnOn = policy.warnOn ?? DEFAULT_CONFIG.policy.warnOn;
  for (const [label, values] of [['policy.failOn', failOn], ['policy.warnOn', warnOn]] as const) {
    if (!Array.isArray(values) || values.some((v) => typeof v !== 'string' || !VALID_SEVERITIES.has(v as Severity))) {
      throw new Error(`${label} must contain valid severities`);
    }
  }

  const customPatterns = secrets.customPatterns ?? DEFAULT_CONFIG.secrets.customPatterns;
  if (!Array.isArray(customPatterns)) throw new Error('secrets.customPatterns must be an array');

  return {
    schemaVersion: 1,
    scan: {
      include: Array.isArray(scan.include) ? scan.include.map(String) : DEFAULT_CONFIG.scan.include,
      exclude: Array.isArray(scan.exclude) ? scan.exclude.map(String) : DEFAULT_CONFIG.scan.exclude,
      maxFileBytes: typeof scan.maxFileBytes === 'number' ? scan.maxFileBytes : DEFAULT_CONFIG.scan.maxFileBytes
    },
    secrets: {
      enabled: typeof secrets.enabled === 'boolean' ? secrets.enabled : DEFAULT_CONFIG.secrets.enabled,
      highEntropy: typeof secrets.highEntropy === 'boolean' ? secrets.highEntropy : DEFAULT_CONFIG.secrets.highEntropy,
      minEntropyLength: typeof secrets.minEntropyLength === 'number' ? secrets.minEntropyLength : DEFAULT_CONFIG.secrets.minEntropyLength,
      customPatterns: customPatterns.map((item, index) => {
        const entry = asObject(item, `secrets.customPatterns[${index}]`);
        if (typeof entry.id !== 'string' || typeof entry.pattern !== 'string') {
          throw new Error(`secrets.customPatterns[${index}] requires id and pattern`);
        }
        const severity = (entry.severity ?? 'high') as Severity;
        if (!VALID_SEVERITIES.has(severity)) throw new Error(`Invalid severity for custom pattern ${entry.id}`);
        // Validate regex early as configuration error.
        new RegExp(entry.pattern, 'g');
        return {
          id: entry.id,
          pattern: entry.pattern,
          severity,
          ...(typeof entry.description === 'string' ? { description: entry.description } : {})
        };
      })
    },
    policy: {
      failOn: (failOn as string[]).map((v) => v as Severity),
      warnOn: (warnOn as string[]).map((v) => v as Severity),
      requiredScanners: Array.isArray(policy.requiredScanners) ? policy.requiredScanners.map(String) : DEFAULT_CONFIG.policy.requiredScanners
    },
    waiversFile: typeof raw.waiversFile === 'string' ? raw.waiversFile : DEFAULT_CONFIG.waiversFile
  };
}

export async function loadConfig(root: string, explicitPath?: string): Promise<SentryCodeConfig> {
  const path = explicitPath ? resolve(root, explicitPath) : resolve(root, '.sentrycode/config.json');
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as unknown;
    return mergeConfig(asObject(raw, 'config'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT' && !explicitPath) return structuredClone(DEFAULT_CONFIG);
    if (error instanceof SyntaxError) throw new Error(`Invalid JSON in SentryCode config: ${path}`);
    throw error;
  }
}
