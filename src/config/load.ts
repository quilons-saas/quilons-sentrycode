import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from './defaults.js';
import type { ScannerFailureMode, SentryCodeConfig, Severity } from '../core/types.js';

const VALID_SEVERITIES = new Set<Severity>(['info', 'low', 'medium', 'high', 'critical']);
const VALID_FAILURE_MODES = new Set<ScannerFailureMode>(['fail', 'warn', 'ignore']);
const VALID_SAST_LANGUAGES = new Set(['javascript', 'typescript', 'python', 'java', 'csharp', 'c', 'cpp', 'rust', 'go']);
const VALID_CI_PROVIDERS = new Set(['auto','github','gitlab','azure-devops','jenkins','gerrit','generic','local']);
const VALID_AUTOMOTIVE_STANDARDS = new Set(['misra-c','misra-cpp','autosar-cpp']);
const VALID_AUTOMOTIVE_TARGETS = new Set(['iso-sae-21434','unece-r155','unece-r156']);

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


function numberRecord(value: unknown, fallback: Record<string, number>, label: string): Record<string, number> {
  if (value === undefined) return { ...fallback };
  const object = asObject(value, label);
  const result: Record<string, number> = {};
  for (const [key, item] of Object.entries(object)) {
    if (typeof item !== 'number' || !Number.isFinite(item)) throw new Error(`${label}.${key} must be a number`);
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
  const dependencyMaintenance = dependencies.maintenance === undefined ? {} : asObject(dependencies.maintenance, 'dependencies.maintenance');
  const licenses = raw.licenses === undefined ? {} : asObject(raw.licenses, 'licenses');
  const vulnerabilities = raw.vulnerabilities === undefined ? {} : asObject(raw.vulnerabilities, 'vulnerabilities');
  const sbom = raw.sbom === undefined ? {} : asObject(raw.sbom, 'sbom');
  const sast = raw.sast === undefined ? {} : asObject(raw.sast, 'sast');
  const externalSast = sast.external === undefined ? {} : asObject(sast.external, 'sast.external');
  const gitAssurance = raw.gitAssurance === undefined ? {} : asObject(raw.gitAssurance, 'gitAssurance');
  const githubAssurance = gitAssurance.github === undefined ? {} : asObject(gitAssurance.github, 'gitAssurance.github');
  const gerritAssurance = gitAssurance.gerrit === undefined ? {} : asObject(gitAssurance.gerrit, 'gitAssurance.gerrit');
  const provenance = raw.provenance === undefined ? {} : asObject(raw.provenance, 'provenance');
  const automotive = raw.automotive === undefined ? {} : asObject(raw.automotive, 'automotive');
  const ci = raw.ci === undefined ? {} : asObject(raw.ci, 'ci');
  const monorepo = raw.monorepo === undefined ? {} : asObject(raw.monorepo, 'monorepo');
  const incremental = raw.incremental === undefined ? {} : asObject(raw.incremental, 'incremental');
  const compliance = raw.compliance === undefined ? {} : asObject(raw.compliance, 'compliance');
  const craReporting = raw.craReporting === undefined ? {} : asObject(raw.craReporting, 'craReporting');
  const offline = raw.offline === undefined ? {} : asObject(raw.offline, 'offline');
  const integrity = raw.integrity === undefined ? {} : asObject(raw.integrity, 'integrity');
  const operations = raw.operations === undefined ? {} : asObject(raw.operations, 'operations');
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
      historyMaxCommits: typeof secrets.historyMaxCommits === 'number' && secrets.historyMaxCommits > 0 ? Math.floor(secrets.historyMaxCommits) : DEFAULT_CONFIG.secrets.historyMaxCommits,
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
      deniedRegistries: stringArray(dependencies.deniedRegistries, DEFAULT_CONFIG.dependencies.deniedRegistries, 'dependencies.deniedRegistries'),
      deniedPackages: stringArray(dependencies.deniedPackages, DEFAULT_CONFIG.dependencies.deniedPackages, 'dependencies.deniedPackages'),
      allowedPackages: stringArray(dependencies.allowedPackages, DEFAULT_CONFIG.dependencies.allowedPackages, 'dependencies.allowedPackages'),
      versionRestrictions: stringRecord(dependencies.versionRestrictions, DEFAULT_CONFIG.dependencies.versionRestrictions, 'dependencies.versionRestrictions'),
      maintenance: {
        enabled: typeof dependencyMaintenance.enabled === 'boolean' ? dependencyMaintenance.enabled : DEFAULT_CONFIG.dependencies.maintenance.enabled,
        metadataFile: typeof dependencyMaintenance.metadataFile === 'string' ? dependencyMaintenance.metadataFile : DEFAULT_CONFIG.dependencies.maintenance.metadataFile,
        maxReleaseAgeDays: typeof dependencyMaintenance.maxReleaseAgeDays === 'number' && dependencyMaintenance.maxReleaseAgeDays >= 0 ? dependencyMaintenance.maxReleaseAgeDays : DEFAULT_CONFIG.dependencies.maintenance.maxReleaseAgeDays,
        denyDeprecated: typeof dependencyMaintenance.denyDeprecated === 'boolean' ? dependencyMaintenance.denyDeprecated : DEFAULT_CONFIG.dependencies.maintenance.denyDeprecated,
        requireMetadata: typeof dependencyMaintenance.requireMetadata === 'boolean' ? dependencyMaintenance.requireMetadata : DEFAULT_CONFIG.dependencies.maintenance.requireMetadata
      }
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
      failOnKnownExploited: typeof vulnerabilities.failOnKnownExploited === 'boolean' ? vulnerabilities.failOnKnownExploited : DEFAULT_CONFIG.vulnerabilities.failOnKnownExploited,
      osv: (() => {
        const rawOsv = vulnerabilities.osv === undefined ? {} : asObject(vulnerabilities.osv, 'vulnerabilities.osv');
        return {
          enabled: typeof rawOsv.enabled === 'boolean' ? rawOsv.enabled : DEFAULT_CONFIG.vulnerabilities.osv.enabled,
          endpoint: typeof rawOsv.endpoint === 'string' ? rawOsv.endpoint : DEFAULT_CONFIG.vulnerabilities.osv.endpoint,
          timeoutMs: typeof rawOsv.timeoutMs === 'number' && rawOsv.timeoutMs > 0 ? rawOsv.timeoutMs : DEFAULT_CONFIG.vulnerabilities.osv.timeoutMs
        };
      })()
    },
    sbom: { defaultFormat: sbomFormat },
    sast: {
      enabled: typeof sast.enabled === 'boolean' ? sast.enabled : DEFAULT_CONFIG.sast.enabled,
      languages: (() => {
        const values = stringArray(sast.languages, DEFAULT_CONFIG.sast.languages, 'sast.languages');
        if (values.some((value) => !VALID_SAST_LANGUAGES.has(value))) throw new Error('sast.languages contains an unsupported language');
        return values as SentryCodeConfig['sast']['languages'];
      })(),
      external: {
        enabled: typeof externalSast.enabled === 'boolean' ? externalSast.enabled : DEFAULT_CONFIG.sast.external.enabled,
        command: typeof externalSast.command === 'string' ? externalSast.command : DEFAULT_CONFIG.sast.external.command,
        args: stringArray(externalSast.args, DEFAULT_CONFIG.sast.external.args, 'sast.external.args'),
        sarifFile: typeof externalSast.sarifFile === 'string' ? externalSast.sarifFile : DEFAULT_CONFIG.sast.external.sarifFile,
        timeoutMs: typeof externalSast.timeoutMs === 'number' && externalSast.timeoutMs > 0 ? externalSast.timeoutMs : DEFAULT_CONFIG.sast.external.timeoutMs
      }
    },
    gitAssurance: {
      enabled: typeof gitAssurance.enabled === 'boolean' ? gitAssurance.enabled : DEFAULT_CONFIG.gitAssurance.enabled,
      requireCleanTree: typeof gitAssurance.requireCleanTree === 'boolean' ? gitAssurance.requireCleanTree : DEFAULT_CONFIG.gitAssurance.requireCleanTree,
      requireSignedCommit: typeof gitAssurance.requireSignedCommit === 'boolean' ? gitAssurance.requireSignedCommit : DEFAULT_CONFIG.gitAssurance.requireSignedCommit,
      allowedEmailDomains: stringArray(gitAssurance.allowedEmailDomains, DEFAULT_CONFIG.gitAssurance.allowedEmailDomains, 'gitAssurance.allowedEmailDomains'),
      github: {
        enabled: typeof githubAssurance.enabled === 'boolean' ? githubAssurance.enabled : DEFAULT_CONFIG.gitAssurance.github.enabled,
        tokenEnv: typeof githubAssurance.tokenEnv === 'string' ? githubAssurance.tokenEnv : DEFAULT_CONFIG.gitAssurance.github.tokenEnv,
        apiBaseUrl: typeof githubAssurance.apiBaseUrl === 'string' ? githubAssurance.apiBaseUrl : DEFAULT_CONFIG.gitAssurance.github.apiBaseUrl,
        requireProtectedBranch: typeof githubAssurance.requireProtectedBranch === 'boolean' ? githubAssurance.requireProtectedBranch : DEFAULT_CONFIG.gitAssurance.github.requireProtectedBranch,
        minimumApprovals: typeof githubAssurance.minimumApprovals === 'number' && githubAssurance.minimumApprovals >= 0 ? Math.floor(githubAssurance.minimumApprovals) : DEFAULT_CONFIG.gitAssurance.github.minimumApprovals,
        requireStatusChecks: typeof githubAssurance.requireStatusChecks === 'boolean' ? githubAssurance.requireStatusChecks : DEFAULT_CONFIG.gitAssurance.github.requireStatusChecks
      },
      gerrit: {
        enabled: typeof gerritAssurance.enabled === 'boolean' ? gerritAssurance.enabled : DEFAULT_CONFIG.gitAssurance.gerrit.enabled,
        apiBaseUrl: typeof gerritAssurance.apiBaseUrl === 'string' ? gerritAssurance.apiBaseUrl : DEFAULT_CONFIG.gitAssurance.gerrit.apiBaseUrl,
        authMode: gerritAssurance.authMode === 'basic' ? 'basic' : 'bearer',
        tokenEnv: typeof gerritAssurance.tokenEnv === 'string' ? gerritAssurance.tokenEnv : DEFAULT_CONFIG.gitAssurance.gerrit.tokenEnv,
        usernameEnv: typeof gerritAssurance.usernameEnv === 'string' ? gerritAssurance.usernameEnv : DEFAULT_CONFIG.gitAssurance.gerrit.usernameEnv,
        passwordEnv: typeof gerritAssurance.passwordEnv === 'string' ? gerritAssurance.passwordEnv : DEFAULT_CONFIG.gitAssurance.gerrit.passwordEnv,
        requiredLabels: numberRecord(gerritAssurance.requiredLabels, DEFAULT_CONFIG.gitAssurance.gerrit.requiredLabels, 'gitAssurance.gerrit.requiredLabels'),
        publishReview: typeof gerritAssurance.publishReview === 'boolean' ? gerritAssurance.publishReview : DEFAULT_CONFIG.gitAssurance.gerrit.publishReview,
        voteLabel: typeof gerritAssurance.voteLabel === 'string' ? gerritAssurance.voteLabel : DEFAULT_CONFIG.gitAssurance.gerrit.voteLabel,
        passVote: typeof gerritAssurance.passVote === 'number' ? gerritAssurance.passVote : DEFAULT_CONFIG.gitAssurance.gerrit.passVote,
        warnVote: typeof gerritAssurance.warnVote === 'number' ? gerritAssurance.warnVote : DEFAULT_CONFIG.gitAssurance.gerrit.warnVote,
        failVote: typeof gerritAssurance.failVote === 'number' ? gerritAssurance.failVote : DEFAULT_CONFIG.gitAssurance.gerrit.failVote,
        notify: ['NONE','OWNER','OWNER_REVIEWERS','ALL'].includes(String(gerritAssurance.notify)) ? gerritAssurance.notify as SentryCodeConfig['gitAssurance']['gerrit']['notify'] : DEFAULT_CONFIG.gitAssurance.gerrit.notify,
        failClosed: typeof gerritAssurance.failClosed === 'boolean' ? gerritAssurance.failClosed : DEFAULT_CONFIG.gitAssurance.gerrit.failClosed,
        timeoutMs: typeof gerritAssurance.timeoutMs === 'number' && gerritAssurance.timeoutMs > 0 ? gerritAssurance.timeoutMs : DEFAULT_CONFIG.gitAssurance.gerrit.timeoutMs
      }
    },
    provenance: {
      enabled: typeof provenance.enabled === 'boolean' ? provenance.enabled : DEFAULT_CONFIG.provenance.enabled,
      artifactPaths: stringArray(provenance.artifactPaths, DEFAULT_CONFIG.provenance.artifactPaths, 'provenance.artifactPaths'),
      signingPrivateKeyFile: typeof provenance.signingPrivateKeyFile === 'string' ? provenance.signingPrivateKeyFile : DEFAULT_CONFIG.provenance.signingPrivateKeyFile,
      signingPublicKeyFile: typeof provenance.signingPublicKeyFile === 'string' ? provenance.signingPublicKeyFile : DEFAULT_CONFIG.provenance.signingPublicKeyFile
    },
    automotive: {
      enabled: typeof automotive.enabled === 'boolean' ? automotive.enabled : DEFAULT_CONFIG.automotive.enabled,
      importDirectory: typeof automotive.importDirectory === 'string' ? automotive.importDirectory : DEFAULT_CONFIG.automotive.importDirectory,
      deviationsFile: typeof automotive.deviationsFile === 'string' ? automotive.deviationsFile : DEFAULT_CONFIG.automotive.deviationsFile,
      acceptedStandards: (() => {
        const values = stringArray(automotive.acceptedStandards, DEFAULT_CONFIG.automotive.acceptedStandards, 'automotive.acceptedStandards');
        if (values.some((value) => !VALID_AUTOMOTIVE_STANDARDS.has(value))) throw new Error('automotive.acceptedStandards contains an unsupported standard');
        return values as SentryCodeConfig['automotive']['acceptedStandards'];
      })(),
      requireDeviationApproval: typeof automotive.requireDeviationApproval === 'boolean' ? automotive.requireDeviationApproval : DEFAULT_CONFIG.automotive.requireDeviationApproval,
      requireInputs: typeof automotive.requireInputs === 'boolean' ? automotive.requireInputs : DEFAULT_CONFIG.automotive.requireInputs,
      evidenceTargets: (() => {
        const values = stringArray(automotive.evidenceTargets, DEFAULT_CONFIG.automotive.evidenceTargets, 'automotive.evidenceTargets');
        if (values.some((value) => !VALID_AUTOMOTIVE_TARGETS.has(value))) throw new Error('automotive.evidenceTargets contains an unsupported target');
        return values as SentryCodeConfig['automotive']['evidenceTargets'];
      })()
    },
    ci: {
      enabled: typeof ci.enabled === 'boolean' ? ci.enabled : DEFAULT_CONFIG.ci.enabled,
      provider: (() => {
        const provider = typeof ci.provider === 'string' ? ci.provider : DEFAULT_CONFIG.ci.provider;
        if (!VALID_CI_PROVIDERS.has(provider)) throw new Error('ci.provider is unsupported');
        return provider as SentryCodeConfig['ci']['provider'];
      })(),
      annotations: typeof ci.annotations === 'boolean' ? ci.annotations : DEFAULT_CONFIG.ci.annotations
    },
    monorepo: {
      enabled: typeof monorepo.enabled === 'boolean' ? monorepo.enabled : DEFAULT_CONFIG.monorepo.enabled,
      serviceRoots: stringArray(monorepo.serviceRoots, DEFAULT_CONFIG.monorepo.serviceRoots, 'monorepo.serviceRoots'),
      discoverWorkspaces: typeof monorepo.discoverWorkspaces === 'boolean' ? monorepo.discoverWorkspaces : DEFAULT_CONFIG.monorepo.discoverWorkspaces
    },
    incremental: {
      enabled: typeof incremental.enabled === 'boolean' ? incremental.enabled : DEFAULT_CONFIG.incremental.enabled,
      baseRef: typeof incremental.baseRef === 'string' ? incremental.baseRef : DEFAULT_CONFIG.incremental.baseRef,
      headRef: typeof incremental.headRef === 'string' ? incremental.headRef : DEFAULT_CONFIG.incremental.headRef,
      cacheFile: typeof incremental.cacheFile === 'string' ? incremental.cacheFile : DEFAULT_CONFIG.incremental.cacheFile,
      scannerTimeoutMs: typeof incremental.scannerTimeoutMs === 'number' ? incremental.scannerTimeoutMs : DEFAULT_CONFIG.incremental.scannerTimeoutMs
    },
    compliance: {
      enabled: typeof compliance.enabled === 'boolean' ? compliance.enabled : DEFAULT_CONFIG.compliance.enabled,
      tenant: typeof compliance.tenant === 'string' ? compliance.tenant : DEFAULT_CONFIG.compliance.tenant,
      project: typeof compliance.project === 'string' ? compliance.project : DEFAULT_CONFIG.compliance.project,
      storeDirectory: typeof compliance.storeDirectory === 'string' ? compliance.storeDirectory : DEFAULT_CONFIG.compliance.storeDirectory,
      endpoint: typeof compliance.endpoint === 'string' ? compliance.endpoint : DEFAULT_CONFIG.compliance.endpoint,
      tokenEnv: typeof compliance.tokenEnv === 'string' ? compliance.tokenEnv : DEFAULT_CONFIG.compliance.tokenEnv,
      timeoutMs: typeof compliance.timeoutMs === 'number' && compliance.timeoutMs >= 0 ? compliance.timeoutMs : DEFAULT_CONFIG.compliance.timeoutMs,
      listenHost: typeof compliance.listenHost === 'string' ? compliance.listenHost : DEFAULT_CONFIG.compliance.listenHost,
      listenPort: typeof compliance.listenPort === 'number' && compliance.listenPort >= 0 && compliance.listenPort <= 65535 ? compliance.listenPort : DEFAULT_CONFIG.compliance.listenPort,
      apiTokenEnv: typeof compliance.apiTokenEnv === 'string' ? compliance.apiTokenEnv : DEFAULT_CONFIG.compliance.apiTokenEnv,
      authMode: compliance.authMode === 'hmac' ? 'hmac' : 'static',
      hmacSecretEnv: typeof compliance.hmacSecretEnv === 'string' ? compliance.hmacSecretEnv : DEFAULT_CONFIG.compliance.hmacSecretEnv,
      tokenIssuer: typeof compliance.tokenIssuer === 'string' ? compliance.tokenIssuer : DEFAULT_CONFIG.compliance.tokenIssuer,
      tokenAudience: typeof compliance.tokenAudience === 'string' ? compliance.tokenAudience : DEFAULT_CONFIG.compliance.tokenAudience
    },
    craReporting: {
      enabled: typeof craReporting.enabled === 'boolean' ? craReporting.enabled : DEFAULT_CONFIG.craReporting.enabled,
      endpoint: typeof craReporting.endpoint === 'string' ? craReporting.endpoint : DEFAULT_CONFIG.craReporting.endpoint,
      tokenEnv: typeof craReporting.tokenEnv === 'string' ? craReporting.tokenEnv : DEFAULT_CONFIG.craReporting.tokenEnv,
      timeoutMs: typeof craReporting.timeoutMs === 'number' && craReporting.timeoutMs >= 0 ? craReporting.timeoutMs : DEFAULT_CONFIG.craReporting.timeoutMs,
      severities: (() => {
        const values = stringArray(craReporting.severities, DEFAULT_CONFIG.craReporting.severities, 'craReporting.severities');
        if (values.some((value) => !VALID_SEVERITIES.has(value as Severity))) throw new Error('craReporting.severities must contain valid severities');
        return values as Severity[];
      })(),
      findingTypes: stringArray(craReporting.findingTypes, DEFAULT_CONFIG.craReporting.findingTypes, 'craReporting.findingTypes')
    },
    offline: {
      enabled: typeof offline.enabled === 'boolean' ? offline.enabled : DEFAULT_CONFIG.offline.enabled,
      requireSignedIntelligenceBundles: typeof offline.requireSignedIntelligenceBundles === 'boolean' ? offline.requireSignedIntelligenceBundles : DEFAULT_CONFIG.offline.requireSignedIntelligenceBundles,
      intelligencePublicKeyFile: typeof offline.intelligencePublicKeyFile === 'string' ? offline.intelligencePublicKeyFile : DEFAULT_CONFIG.offline.intelligencePublicKeyFile
    },
    integrity: {
      requireSignedConfig: typeof integrity.requireSignedConfig === 'boolean' ? integrity.requireSignedConfig : DEFAULT_CONFIG.integrity.requireSignedConfig,
      configSignatureFile: typeof integrity.configSignatureFile === 'string' ? integrity.configSignatureFile : DEFAULT_CONFIG.integrity.configSignatureFile,
      publicKeyFile: typeof integrity.publicKeyFile === 'string' ? integrity.publicKeyFile : DEFAULT_CONFIG.integrity.publicKeyFile,
      auditLogFile: typeof integrity.auditLogFile === 'string' ? integrity.auditLogFile : DEFAULT_CONFIG.integrity.auditLogFile,
      evidenceManifests: typeof integrity.evidenceManifests === 'boolean' ? integrity.evidenceManifests : DEFAULT_CONFIG.integrity.evidenceManifests,
      evidenceSigningPrivateKeyFile: typeof integrity.evidenceSigningPrivateKeyFile === 'string' ? integrity.evidenceSigningPrivateKeyFile : DEFAULT_CONFIG.integrity.evidenceSigningPrivateKeyFile,
      evidenceSigningPublicKeyFile: typeof integrity.evidenceSigningPublicKeyFile === 'string' ? integrity.evidenceSigningPublicKeyFile : DEFAULT_CONFIG.integrity.evidenceSigningPublicKeyFile
    },
    operations: {
      backupDirectory: typeof operations.backupDirectory === 'string' ? operations.backupDirectory : DEFAULT_CONFIG.operations.backupDirectory,
      retentionDays: typeof operations.retentionDays === 'number' && operations.retentionDays > 0 ? operations.retentionDays : DEFAULT_CONFIG.operations.retentionDays
    },
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

function applyEnvironmentOverrides(config: SentryCodeConfig, env: Record<string, string | undefined> = process.env): SentryCodeConfig {
  const next = structuredClone(config);
  const provider = env.SENTRYCODE_CI_PROVIDER;
  if (provider) {
    if (!VALID_CI_PROVIDERS.has(provider)) throw new Error('SENTRYCODE_CI_PROVIDER is unsupported');
    next.ci.provider = provider as SentryCodeConfig['ci']['provider'];
  }
  if (env.SENTRYCODE_INCREMENTAL_BASE !== undefined) next.incremental.baseRef = env.SENTRYCODE_INCREMENTAL_BASE;
  if (env.SENTRYCODE_INCREMENTAL_HEAD) next.incremental.headRef = env.SENTRYCODE_INCREMENTAL_HEAD;
  if (env.SENTRYCODE_SCANNER_TIMEOUT_MS) {
    const value = Number(env.SENTRYCODE_SCANNER_TIMEOUT_MS);
    if (!Number.isFinite(value) || value < 0) throw new Error('SENTRYCODE_SCANNER_TIMEOUT_MS must be a non-negative number');
    next.incremental.scannerTimeoutMs = value;
  }
  if (env.SENTRYCODE_DISABLE_CI_ANNOTATIONS === 'true') next.ci.annotations = false;
  if (env.SENTRYCODE_GERRIT_URL !== undefined) next.gitAssurance.gerrit.apiBaseUrl = env.SENTRYCODE_GERRIT_URL;
  if (env.SENTRYCODE_GERRIT_TOKEN_ENV) next.gitAssurance.gerrit.tokenEnv = env.SENTRYCODE_GERRIT_TOKEN_ENV;
  if (env.SENTRYCODE_GERRIT_USERNAME_ENV) next.gitAssurance.gerrit.usernameEnv = env.SENTRYCODE_GERRIT_USERNAME_ENV;
  if (env.SENTRYCODE_GERRIT_PASSWORD_ENV) next.gitAssurance.gerrit.passwordEnv = env.SENTRYCODE_GERRIT_PASSWORD_ENV;
  if (env.SENTRYCODE_COMPLIANCE_TENANT !== undefined) next.compliance.tenant = env.SENTRYCODE_COMPLIANCE_TENANT;
  if (env.SENTRYCODE_COMPLIANCE_PROJECT !== undefined) next.compliance.project = env.SENTRYCODE_COMPLIANCE_PROJECT;
  if (env.SENTRYCODE_COMPLIANCE_ENDPOINT !== undefined) next.compliance.endpoint = env.SENTRYCODE_COMPLIANCE_ENDPOINT;
  if (env.SENTRYCODE_DISABLE_COMPLIANCE_PUBLISH === 'true') next.compliance.enabled = false;
  if (env.SENTRYCODE_CRA_ENDPOINT !== undefined) next.craReporting.endpoint = env.SENTRYCODE_CRA_ENDPOINT;
  if (env.SENTRYCODE_DISABLE_CRA_REPORTING === 'true') next.craReporting.enabled = false;
  if (env.SENTRYCODE_OFFLINE === 'true') next.offline.enabled = true;
  return next;
}

export async function loadConfig(root: string, explicitPath?: string): Promise<SentryCodeConfig> {
  const path = explicitPath ? resolve(root, explicitPath) : resolve(root, '.sentrycode/config.json');
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as unknown;
    return applyEnvironmentOverrides(mergeConfig(asObject(raw, 'config')));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT' && !explicitPath) return applyEnvironmentOverrides(structuredClone(DEFAULT_CONFIG));
    if (error instanceof SyntaxError) throw new Error(`Invalid JSON in SentryCode config: ${path}`);
    throw error;
  }
}
