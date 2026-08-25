import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from './defaults.js';
import type { ScannerFailureMode, SentryCodeConfig, Severity } from '../core/types.js';

const VALID_SEVERITIES = new Set<Severity>(['info', 'low', 'medium', 'high', 'critical']);
const VALID_FAILURE_MODES = new Set<ScannerFailureMode>(['fail', 'warn', 'ignore']);

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function stringArray(value: unknown, fallback: string[], label: string): string[] {
  if (value === undefined) return [...fallback];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) throw new Error(`${label} must be an array of strings`);
  return [...value];
}

function stringRecord(value: unknown, fallback: Record<string, string>, label: string): Record<string, string> {
  if (value === undefined) return { ...fallback };
  const object = asObject(value, label);
  const result: Record<string, string> = {};
  for (const [key, item] of Object.entries(object)) {
    if (typeof item !== 'string') throw new Error(`${label}.${key} must be a string`);
    result[key] = item;
  }
  return result;
}

function failureModeRecord(value: unknown, fallback: Record<string, ScannerFailureMode>, label: string): Record<string, ScannerFailureMode> {
  const raw = stringRecord(value, fallback, label);
  for (const [key, mode] of Object.entries(raw)) {
    if (!VALID_FAILURE_MODES.has(mode as ScannerFailureMode)) throw new Error(`${label}.${key} must be fail, warn, or ignore`);
  }
  return raw as Record<string, ScannerFailureMode>;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function mergeConfig(raw: Record<string, unknown>): SentryCodeConfig {
  if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1) throw new Error('Unsupported config schemaVersion; expected 1');
  const scan = raw.scan === undefined ? {} : asObject(raw.scan, 'scan');
  const secrets = raw.secrets === undefined ? {} : asObject(raw.secrets, 'secrets');
  const dependencies = raw.dependencies === undefined ? {} : asObject(raw.dependencies, 'dependencies');
  const licenses = raw.licenses === undefined ? {} : asObject(raw.licenses, 'licenses');
  const vulnerabilities = raw.vulnerabilities === undefined ? {} : asObject(raw.vulnerabilities, 'vulnerabilities');
  const sbom = raw.sbom === undefined ? {} : asObject(raw.sbom, 'sbom');
  const policy = raw.policy === undefined ? {} : asObject(raw.policy, 'policy');
  const policyContext = policy.context === undefined ? {} : asObject(policy.context, 'policy.context');
  const opa = policy.opa === undefined ? {} : asObject(policy.opa, 'policy.opa');
  const waivers = raw.waivers === undefined ? {} : asObject(raw.waivers, 'waivers');

  const failOn = policy.failOn ?? DEFAULT_CONFIG.policy.failOn;
  const warnOn = policy.warnOn ?? DEFAULT_CONFIG.policy.warnOn;
  for (const [label, values] of [['policy.failOn', failOn], ['policy.warnOn', warnOn]] as const) {
    if (!Array.isArray(values) || values.some((v) => typeof v !== 'string' || !VALID_SEVERITIES.has(v as Severity))) {
      throw new Error(`${label} must contain valid severities`);
    }
  }

  const customPatterns = secrets.customPatterns ?? DEFAULT_CONFIG.secrets.customPatterns;
  if (!Array.isArray(customPatterns)) throw new Error('secrets.customPatterns must be an array');
  const unknownLicense = licenses.unknown ?? DEFAULT_CONFIG.licenses.unknown;
  if (!['allow', 'warn', 'fail'].includes(String(unknownLicense))) throw new Error('licenses.unknown must be allow, warn, or fail');
  const sbomFormat = sbom.defaultFormat ?? DEFAULT_CONFIG.sbom.defaultFormat;
  if (sbomFormat !== 'cyclonedx' && sbomFormat !== 'spdx') throw new Error('sbom.defaultFormat must be cyclonedx or spdx');

  const legacyWaiverFile = typeof raw.waiversFile === 'string' ? raw.waiversFile : undefined;
  const waiverFile = typeof waivers.file === 'string' ? waivers.file : legacyWaiverFile ?? DEFAULT_CONFIG.waivers.file;
  const maxDurationDays = typeof waivers.maxDurationDays === 'number' ? waivers.maxDurationDays : DEFAULT_CONFIG.waivers.maxDurationDays;
  if (!Number.isFinite(maxDurationDays) || maxDurationDays <= 0) throw new Error('waivers.maxDurationDays must be a positive number');
  const contextTenant = optionalString(policyContext.tenant, 'policy.context.tenant');
  const contextProject = optionalString(policyContext.project, 'policy.context.project');
  const contextService = optionalString(policyContext.service, 'policy.context.service');

  return {
    schemaVersion: 1,
    scan: {
      include: stringArray(scan.include, DEFAULT_CONFIG.scan.include, 'scan.include'),
      exclude: stringArray(scan.exclude, DEFAULT_CONFIG.scan.exclude, 'scan.exclude'),
      maxFileBytes: typeof scan.maxFileBytes === 'number' ? scan.maxFileBytes : DEFAULT_CONFIG.scan.maxFileBytes
    },
    secrets: {
      enabled: typeof secrets.enabled === 'boolean' ? secrets.enabled : DEFAULT_CONFIG.secrets.enabled,
      highEntropy: typeof secrets.highEntropy === 'boolean' ? secrets.highEntropy : DEFAULT_CONFIG.secrets.highEntropy,
      minEntropyLength: typeof secrets.minEntropyLength === 'number' ? secrets.minEntropyLength : DEFAULT_CONFIG.secrets.minEntropyLength,
      customPatterns: customPatterns.map((item, index) => {
        const entry = asObject(item, `secrets.customPatterns[${index}]`);
        if (typeof entry.id !== 'string' || typeof entry.pattern !== 'string') throw new Error(`secrets.customPatterns[${index}] requires id and pattern`);
        const severity = (entry.severity ?? 'high') as Severity;
        if (!VALID_SEVERITIES.has(severity)) throw new Error(`Invalid severity for custom pattern ${entry.id}`);
        new RegExp(entry.pattern, 'g');
        return { id: entry.id, pattern: entry.pattern, severity, ...(typeof entry.description === 'string' ? { description: entry.description } : {}) };
      })
    },
    dependencies: {
      enabled: typeof dependencies.enabled === 'boolean' ? dependencies.enabled : DEFAULT_CONFIG.dependencies.enabled,
      includeDev: typeof dependencies.includeDev === 'boolean' ? dependencies.includeDev : DEFAULT_CONFIG.dependencies.includeDev,
      allowedRegistries: stringArray(dependencies.allowedRegistries, DEFAULT_CONFIG.dependencies.allowedRegistries, 'dependencies.allowedRegistries'),
      deniedPackages: stringArray(dependencies.deniedPackages, DEFAULT_CONFIG.dependencies.deniedPackages, 'dependencies.deniedPackages'),
      allowedPackages: stringArray(dependencies.allowedPackages, DEFAULT_CONFIG.dependencies.allowedPackages, 'dependencies.allowedPackages'),
      versionRestrictions: stringRecord(dependencies.versionRestrictions, DEFAULT_CONFIG.dependencies.versionRestrictions, 'dependencies.versionRestrictions')
    },
    licenses: {
      enabled: typeof licenses.enabled === 'boolean' ? licenses.enabled : DEFAULT_CONFIG.licenses.enabled,
      allowed: stringArray(licenses.allowed, DEFAULT_CONFIG.licenses.allowed, 'licenses.allowed'),
      denied: stringArray(licenses.denied, DEFAULT_CONFIG.licenses.denied, 'licenses.denied'),
      reviewRequired: stringArray(licenses.reviewRequired, DEFAULT_CONFIG.licenses.reviewRequired, 'licenses.reviewRequired'),
      unknown: unknownLicense as 'allow' | 'warn' | 'fail',
      overrides: stringRecord(licenses.overrides, DEFAULT_CONFIG.licenses.overrides, 'licenses.overrides')
    },
    vulnerabilities: {
      enabled: typeof vulnerabilities.enabled === 'boolean' ? vulnerabilities.enabled : DEFAULT_CONFIG.vulnerabilities.enabled,
      databaseFile: typeof vulnerabilities.databaseFile === 'string' ? vulnerabilities.databaseFile : DEFAULT_CONFIG.vulnerabilities.databaseFile,
      failOnKnownExploited: typeof vulnerabilities.failOnKnownExploited === 'boolean' ? vulnerabilities.failOnKnownExploited : DEFAULT_CONFIG.vulnerabilities.failOnKnownExploited
    },
    sbom: { defaultFormat: sbomFormat },
    policy: {
      failOn: (failOn as string[]).map((v) => v as Severity),
      warnOn: (warnOn as string[]).map((v) => v as Severity),
      requiredScanners: stringArray(policy.requiredScanners, DEFAULT_CONFIG.policy.requiredScanners, 'policy.requiredScanners'),
      directory: typeof policy.directory === 'string' ? policy.directory : DEFAULT_CONFIG.policy.directory,
      scannerFailureModes: failureModeRecord(policy.scannerFailureModes, DEFAULT_CONFIG.policy.scannerFailureModes, 'policy.scannerFailureModes'),
      context: {
        ...(contextTenant ? { tenant: contextTenant } : {}),
        ...(contextProject ? { project: contextProject } : {}),
        ...(contextService ? { service: contextService } : {})
      },
      opa: {
        enabled: typeof opa.enabled === 'boolean' ? opa.enabled : DEFAULT_CONFIG.policy.opa.enabled,
        binary: typeof opa.binary === 'string' ? opa.binary : DEFAULT_CONFIG.policy.opa.binary,
        query: typeof opa.query === 'string' ? opa.query : DEFAULT_CONFIG.policy.opa.query,
        policyFiles: stringArray(opa.policyFiles, DEFAULT_CONFIG.policy.opa.policyFiles, 'policy.opa.policyFiles')
      }
    },
    waivers: {
      file: waiverFile,
      requireApproval: typeof waivers.requireApproval === 'boolean' ? waivers.requireApproval : DEFAULT_CONFIG.waivers.requireApproval,
      requireTicket: typeof waivers.requireTicket === 'boolean' ? waivers.requireTicket : DEFAULT_CONFIG.waivers.requireTicket,
      maxDurationDays
    },
    waiversFile: waiverFile
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
