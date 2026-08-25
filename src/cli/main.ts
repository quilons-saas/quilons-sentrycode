#!/usr/bin/env node
import { mkdir, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { resolveRepository } from '../core/repository.js';
import { loadConfig } from '../config/load.js';
import { runScan } from '../core/engine.js';
import { SecretsScanner } from '../scanners/secrets/scanner.js';
import { DependencyScanner } from '../scanners/dependencies/scanner.js';
import { SastScanner } from '../scanners/sast/scanner.js';
import { GitAssuranceScanner } from '../scanners/git/scanner.js';
import { ProvenanceScanner } from '../scanners/provenance.js';
import { AutomotiveScanner } from '../scanners/automotive/scanner.js';
import { renderSarif } from '../reporting/sarif.js';
import { buildStatement, collectArtifacts, signStatement, verifyAttestation, type SignedAttestation } from '../provenance/attestation.js';
import { readFile } from 'node:fs/promises';
import { discoverDependencies } from '../dependencies/discover.js';
import { dependencySnapshotAtRef, diffDependencies } from '../dependencies/diff.js';
import { cyclonedxSbom, spdxSbom } from '../sbom/generate.js';
import { renderConsole } from '../reporting/console.js';
import { renderJson, writeJsonReport } from '../reporting/json.js';
import { loadPolicyDocuments } from '../policy/documents.js';
import { resolvePolicy } from '../policy/resolve.js';
import { buildReleaseDecision } from '../policy/release.js';
import { EXIT_CODES } from './exit-codes.js';
import { detectCi } from '../ci/context.js';
import { renderCiAnnotations } from '../ci/annotations.js';
import { buildIncrementalPlan } from '../incremental/plan.js';
import { writeIncrementalCache } from '../incremental/cache.js';
import { discoverServices } from '../monorepo/discover.js';
import type { PolicyContext, ScanReport, SentryCodeConfig } from '../core/types.js';
import { complianceIdentity } from '../compliance/scope.js';
import { loadPluginManifest } from '../compliance/manifest.js';
import { buildPublication } from '../compliance/publication.js';
import { LocalComplianceStore } from '../compliance/store.js';
import { HttpCompliancePublisher } from '../compliance/publisher.js';
import { SentryCodeComplianceService } from '../compliance/service.js';
import { startComplianceServer } from '../compliance/server.js';
import { importVulnerabilityBundle } from '../enterprise/intelligence.js';
import { signFile, verifyFile } from '../enterprise/integrity.js';
import { appendAuditEvent } from '../enterprise/audit.js';
import { createBackup, restoreBackup, applyRetention, applyComplianceRetention } from '../enterprise/backup.js';
import { runDiagnostics } from '../enterprise/diagnostics.js';

interface CommonOptions { path: string; config?: string; output?: string; service?: string; base?: string; head?: string; full?: boolean; ci?: boolean; tenant?: string; project?: string; runId?: string; }
interface ScanOptions extends CommonOptions { command: 'scan' | 'check'; format: 'console' | 'json' | 'sarif'; }
interface SbomOptions extends CommonOptions { command: 'sbom'; format: 'cyclonedx' | 'spdx'; }
interface DiffOptions extends CommonOptions { command: 'dependencies-diff'; base: string; head: string; format: 'console' | 'json'; }
interface PolicyOptions extends CommonOptions { command: 'policy-validate' | 'policy-evaluate'; format: 'console' | 'json' | 'sarif'; }
interface ReleaseOptions extends CommonOptions { command: 'release-check'; format: 'console' | 'json' | 'sarif'; }
interface ProvenanceOptions extends CommonOptions { command: 'provenance-attest'; artifact: string[]; key?: string; }
interface VerifyOptions extends CommonOptions { command: 'provenance-verify'; attestation: string; publicKey: string; }
interface ServicesOptions extends CommonOptions { command: 'services'; format: 'console' | 'json'; }
interface ComplianceOptions extends CommonOptions { command: 'compliance-manifest' | 'compliance-health' | 'compliance-ready' | 'compliance-publish' | 'compliance-runs' | 'compliance-run' | 'compliance-serve'; format: 'console' | 'json'; }
interface EnterpriseOptions extends CommonOptions { command: 'enterprise-diagnostics' | 'enterprise-backup' | 'enterprise-retention' | 'enterprise-restore' | 'intelligence-import' | 'config-sign' | 'config-verify'; format: 'console' | 'json'; bundle?: string; backup?: string; key?: string; publicKey?: string; }

type CliOptions = ScanOptions | SbomOptions | DiffOptions | PolicyOptions | ReleaseOptions | ProvenanceOptions | VerifyOptions | ServicesOptions | ComplianceOptions | EnterpriseOptions;

function usage(): string {
  return `QUILONS SentryCode

Usage:
  sentrycode scan [path] [--config FILE] [--service NAME] [--base REF] [--head REF] [--full] [--ci] [--format console|json|sarif] [--output FILE]
  sentrycode check [path] [--config FILE] [--service NAME] [--base REF] [--head REF] [--full] [--ci] [--format console|json|sarif] [--output FILE]
  sentrycode sbom [path] [--config FILE] [--format cyclonedx|spdx] [--output FILE]
  sentrycode dependencies diff [path] --base REF [--head REF] [--format console|json] [--output FILE]
  sentrycode policy validate [path] [--config FILE] [--service NAME] [--format console|json]
  sentrycode policy evaluate [path] [--config FILE] [--service NAME] [--format console|json] [--output FILE]
  sentrycode release check [path] [--config FILE] [--service NAME] [--format console|json|sarif] [--output FILE]
  sentrycode provenance attest [path] --artifact FILE [--artifact FILE...] [--key PRIVATE.pem] [--output FILE]
  sentrycode provenance verify [path] --attestation FILE --public-key PUBLIC.pem
  sentrycode services [path] [--format console|json]
  sentrycode compliance manifest [path] [--format console|json]
  sentrycode compliance health [path] [--format console|json]
  sentrycode compliance ready [path] [--format console|json]
  sentrycode compliance publish [path] [--tenant ID] [--project ID] [--service NAME] [--format console|json]
  sentrycode compliance runs [path] [--tenant ID] [--project ID] [--format console|json]
  sentrycode compliance run [path] --run-id ID [--tenant ID] [--project ID] [--format console|json]
  sentrycode compliance serve [path]
  sentrycode intelligence import [path] --bundle FILE [--public-key PUBLIC.pem]
  sentrycode enterprise diagnostics [path] [--format console|json]
  sentrycode enterprise backup [path]
  sentrycode enterprise restore [path] --backup PATH
  sentrycode enterprise retention [path]
  sentrycode config sign [path] --key PRIVATE.pem
  sentrycode config verify [path] --public-key PUBLIC.pem

Commands:
  scan               Scan repository and evaluate policy.
  check              Alias of scan for CI/policy-gate use.
  sbom               Generate CycloneDX 1.5 or SPDX 2.3 SBOM.
  dependencies diff  Compare dependency state between Git refs.
  policy validate    Validate and resolve hierarchical policy documents.
  policy evaluate    Run scanners and show the effective policy decision.
  release check      Enforce the release gate and emit release.gate evidence.
  provenance attest  Generate in-toto/SLSA-shaped provenance and optional signature.
  provenance verify  Verify a signed provenance attestation.
  services           Discover monorepo services/packages.
  compliance manifest Expose the versioned QUILONS Compliance plugin manifest.
  compliance health   Lightweight plugin health probe.
  compliance ready    Installer/platform readiness probe.
  compliance publish  Run SentryCode and publish tenant/project-scoped evidence.
  compliance runs     List stored SentryCode runs for one tenant/project scope.
  compliance run      Read one stored publication within one tenant/project scope.
  compliance serve    Serve the versioned plugin capability API for QUILONS Compliance.
  intelligence import Import an offline vulnerability intelligence bundle.
  enterprise diagnostics Run on-prem/offline readiness diagnostics.
  enterprise backup   Back up SentryCode operational state.
  enterprise restore  Restore SentryCode operational state from a backup.
  enterprise retention Apply configured retention to backups and local evidence.
  config sign/verify  Sign or verify repository SentryCode configuration.

Exit codes:
  0 PASS/WARN/success
  1 policy/release failure
  2 scan/runtime failure
  3 configuration/usage failure
`;
}

function requireValue(argv: string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${option} requires a value`);
  return value;
}

function parseArgs(argv: string[]): CliOptions | 'help' {
  if (!argv.length || argv.includes('--help') || argv.includes('-h')) return 'help';
  let offset = 1;
  let command: CliOptions['command'];
  if (argv[0] === 'dependencies' && argv[1] === 'diff') { command = 'dependencies-diff'; offset = 2; }
  else if (argv[0] === 'policy' && argv[1] === 'validate') { command = 'policy-validate'; offset = 2; }
  else if (argv[0] === 'policy' && argv[1] === 'evaluate') { command = 'policy-evaluate'; offset = 2; }
  else if (argv[0] === 'release' && argv[1] === 'check') { command = 'release-check'; offset = 2; }
  else if (argv[0] === 'provenance' && argv[1] === 'attest') { command = 'provenance-attest'; offset = 2; }
  else if (argv[0] === 'provenance' && argv[1] === 'verify') { command = 'provenance-verify'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'manifest') { command = 'compliance-manifest'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'health') { command = 'compliance-health'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'ready') { command = 'compliance-ready'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'publish') { command = 'compliance-publish'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'runs') { command = 'compliance-runs'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'run') { command = 'compliance-run'; offset = 2; }
  else if (argv[0] === 'compliance' && argv[1] === 'serve') { command = 'compliance-serve'; offset = 2; }
  else if (argv[0] === 'intelligence' && argv[1] === 'import') { command = 'intelligence-import'; offset = 2; }
  else if (argv[0] === 'enterprise' && argv[1] === 'diagnostics') { command = 'enterprise-diagnostics'; offset = 2; }
  else if (argv[0] === 'enterprise' && argv[1] === 'backup') { command = 'enterprise-backup'; offset = 2; }
  else if (argv[0] === 'enterprise' && argv[1] === 'restore') { command = 'enterprise-restore'; offset = 2; }
  else if (argv[0] === 'enterprise' && argv[1] === 'retention') { command = 'enterprise-retention'; offset = 2; }
  else if (argv[0] === 'config' && argv[1] === 'sign') { command = 'config-sign'; offset = 2; }
  else if (argv[0] === 'config' && argv[1] === 'verify') { command = 'config-verify'; offset = 2; }
  else if (argv[0] === 'scan' || argv[0] === 'check' || argv[0] === 'sbom' || argv[0] === 'services') command = argv[0];
  else throw new Error(`Unknown command: ${argv.slice(0, 2).join(' ')}`);

  let path = process.cwd();
  let config: string | undefined;
  let output: string | undefined;
  let service: string | undefined;
  let base: string | undefined;
  let head = 'HEAD';
  let positionalUsed = false;
  let scanFormat: 'console' | 'json' | 'sarif' = 'console';
  const artifacts: string[] = [];
  let key: string | undefined;
  let attestation: string | undefined;
  let publicKey: string | undefined;
  let sbomFormat: 'cyclonedx' | 'spdx' = 'cyclonedx';
  let full = false;
  let ci = false;
  let tenant: string | undefined;
  let project: string | undefined;
  let runId: string | undefined;
  let bundle: string | undefined;
  let backup: string | undefined;

  for (let i = offset; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--config') { config = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--output') { output = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--service') { service = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--base') { base = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--head') { head = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--full') { full = true; }
    else if (arg === '--ci') { ci = true; }
    else if (arg === '--tenant') { tenant = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--project') { project = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--run-id') { runId = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--bundle') { bundle = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--backup') { backup = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--artifact') { artifacts.push(requireValue(argv, i, arg)); i += 1; }
    else if (arg === '--key') { key = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--attestation') { attestation = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--public-key') { publicKey = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--format') {
      const value = requireValue(argv, i, arg); i += 1;
      if (command === 'sbom') {
        if (value !== 'cyclonedx' && value !== 'spdx') throw new Error('--format for sbom must be cyclonedx or spdx');
        sbomFormat = value;
      } else {
        if (value !== 'console' && value !== 'json' && value !== 'sarif') throw new Error('--format must be console, json, or sarif');
        scanFormat = value;
      }
    } else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else if (!positionalUsed) { path = arg; positionalUsed = true; }
    else throw new Error(`Unexpected argument: ${arg}`);
  }

  const common = { path, ...(config ? { config } : {}), ...(output ? { output } : {}), ...(service ? { service } : {}), ...(base ? { base } : {}), ...(head !== 'HEAD' ? { head } : {}), ...(full ? { full: true } : {}), ...(ci ? { ci: true } : {}), ...(tenant ? { tenant } : {}), ...(project ? { project } : {}), ...(runId ? { runId } : {}) };
  if (command.startsWith('compliance-')) {
    if (scanFormat === 'sarif') throw new Error('compliance commands do not support SARIF format');
    if (command === 'compliance-run' && !runId) throw new Error('compliance run requires --run-id ID');
    return { command: command as ComplianceOptions['command'], ...common, format: scanFormat as 'console' | 'json' };
  }
  if (command.startsWith('enterprise-') || command === 'intelligence-import' || command === 'config-sign' || command === 'config-verify') {
    if (scanFormat === 'sarif') throw new Error('enterprise commands do not support SARIF format');
    if (command === 'intelligence-import' && !bundle) throw new Error('intelligence import requires --bundle FILE');
    if (command === 'enterprise-restore' && !backup) throw new Error('enterprise restore requires --backup PATH');
    if (command === 'config-sign' && !key) throw new Error('config sign requires --key PRIVATE.pem');
    if (command === 'config-verify' && !publicKey) throw new Error('config verify requires --public-key PUBLIC.pem');
    return { command: command as EnterpriseOptions['command'], ...common, format: scanFormat as 'console' | 'json', ...(bundle ? { bundle } : {}), ...(backup ? { backup } : {}), ...(key ? { key } : {}), ...(publicKey ? { publicKey } : {}) };
  }
  if (command === 'dependencies-diff') {
    if (!base) throw new Error('dependencies diff requires --base REF');
    if (scanFormat === 'sarif') throw new Error('dependencies diff does not support SARIF format');
    return { command, ...common, base, head, format: scanFormat };
  }
  if (command === 'sbom') return { command, ...common, format: sbomFormat };
  if (command === 'services') {
    if (scanFormat === 'sarif') throw new Error('services does not support SARIF format');
    return { command, ...common, format: scanFormat };
  }
  if (command === 'provenance-attest') { if (!artifacts.length) throw new Error('provenance attest requires at least one --artifact FILE'); return { command, ...common, artifact: artifacts, ...(key ? { key } : {}) }; }
  if (command === 'provenance-verify') { if (!attestation || !publicKey) throw new Error('provenance verify requires --attestation FILE and --public-key FILE'); return { command, ...common, attestation, publicKey }; }
  if (command === 'policy-validate' || command === 'policy-evaluate' || command === 'release-check') {
    return { command, ...common, format: scanFormat };
  }
  if (command === 'scan' || command === 'check') return { command, ...common, format: scanFormat };
  throw new Error(`Unsupported command: ${command}`);
}

async function writeOutput(root: string, output: string, content: string): Promise<string> {
  const absolute = resolve(root, output);
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, content, 'utf8');
  return absolute;
}

function renderDependencyDiff(changes: ReturnType<typeof diffDependencies>): string {
  if (!changes.length) return 'No dependency changes.\n';
  return `${changes.map((change) => {
    const before = change.before ? `@${change.before.version}` : '';
    const after = change.after ? `@${change.after.version}` : '';
    if (change.kind === 'added') return `ADDED ${change.ecosystem}:${change.name}${after}`;
    if (change.kind === 'removed') return `REMOVED ${change.ecosystem}:${change.name}${before}`;
    return `${change.kind.toUpperCase()} ${change.ecosystem}:${change.name}${before} -> ${after}`;
  }).join('\n')}\n`;
}

function policyContext(repository: string, config: Awaited<ReturnType<typeof loadConfig>>, service?: string): PolicyContext {
  return {
    repository,
    ...(config.policy.context.tenant ? { tenant: config.policy.context.tenant } : {}),
    ...(config.policy.context.project ? { project: config.policy.context.project } : {}),
    ...((service ?? config.policy.context.service) ? { service: service ?? config.policy.context.service } : {})
  };
}

function renderEffectivePolicy(policy: ReturnType<typeof resolvePolicy>): string {
  const sources = policy.sourceDocuments.length
    ? policy.sourceDocuments.map((item) => `${item.level}: ${item.id}@${item.version} (${item.path})`).join('\n')
    : '(configuration baseline only)';
  return `SentryCode policy valid
Fingerprint: ${policy.fingerprint}
Sources:
${sources}
Fail on: ${policy.failOn.join(', ') || '(none)'}
Warn on: ${policy.warnOn.join(', ') || '(none)'}
Required scanners: ${policy.requiredScanners.join(', ') || '(none)'}
Locked fields: ${policy.lockedFields.join(', ') || '(none)'}
`;
}

function renderPolicyEvaluation(report: ScanReport): string {
  const base = renderConsole(report);
  const policy = report.policy.effectivePolicy;
  if (!policy) return `${base}\n`;
  return `${base}

Policy fingerprint: ${policy.fingerprint}
Policy sources: ${policy.sourceDocuments.map((item) => `${item.id}@${item.version}`).join(', ') || 'configuration baseline'}
`;
}

function resolveComplianceIdentity(config: SentryCodeConfig, options: CommonOptions) {
  return complianceIdentity(options.tenant ?? config.compliance.tenant, options.project ?? config.compliance.project);
}

async function publishCompliance(root: string, config: SentryCodeConfig, options: CommonOptions, report: ScanReport) {
  const identity = resolveComplianceIdentity(config, options);
  const manifest = await loadPluginManifest(root);
  const publication = buildPublication(identity, report, manifest.productVersion);
  const store = new LocalComplianceStore(root, config.compliance.storeDirectory);
  await store.publish(identity, publication);
  if (config.compliance.endpoint) {
    const token = process.env[config.compliance.tokenEnv] ?? '';
    await new HttpCompliancePublisher(config.compliance.endpoint, token, config.compliance.timeoutMs).publish(publication);
  }
  return publication;
}

async function main(): Promise<number> {
  let options: CliOptions | 'help';
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { console.error(`Configuration error: ${(error as Error).message}\n`); console.error(usage()); return EXIT_CODES.CONFIGURATION_FAILURE; }
  if (options === 'help') { console.log(usage()); return EXIT_CODES.PASS; }

  try {
    await stat(options.path);
    const repository = await resolveRepository(options.path);

    if (options.command === 'dependencies-diff') {
      const before = await dependencySnapshotAtRef(repository.root, options.base);
      const after = await dependencySnapshotAtRef(repository.root, options.head);
      const changes = diffDependencies(before, after);
      const rendered = options.format === 'json' ? `${JSON.stringify({ schemaVersion: '1.0.0', base: options.base, head: options.head, changes }, null, 2)}\n` : renderDependencyDiff(changes);
      if (options.output) console.log(`Dependency diff written: ${await writeOutput(repository.root, options.output, rendered)}`);
      else process.stdout.write(rendered);
      return EXIT_CODES.PASS;
    }

    let config;
    try { config = await loadConfig(repository.root, options.config); }
    catch (error) { console.error(`Configuration error: ${(error as Error).message}`); return EXIT_CODES.CONFIGURATION_FAILURE; }

    const configPath = options.config ?? '.sentrycode/config.json';
    if (config.integrity.requireSignedConfig && options.command !== 'config-sign') {
      if (!config.integrity.publicKeyFile) { console.error('Configuration error: integrity.publicKeyFile is required when signed configuration is enforced'); return EXIT_CODES.CONFIGURATION_FAILURE; }
      const ok = await verifyFile(repository.root, configPath, config.integrity.configSignatureFile, config.integrity.publicKeyFile);
      if (!ok) { console.error('Configuration error: SentryCode configuration signature verification failed'); return EXIT_CODES.CONFIGURATION_FAILURE; }
    }

    if (options.command === 'config-sign') {
      const signature = await signFile(repository.root, configPath, options.key!, config.integrity.configSignatureFile);
      await appendAuditEvent(repository.root, config.integrity.auditLogFile, 'config.signed', { file: configPath, fingerprint: signature.publicKeyFingerprint });
      process.stdout.write(`${JSON.stringify(signature, null, 2)}\n`); return EXIT_CODES.PASS;
    }
    if (options.command === 'config-verify') {
      const ok = await verifyFile(repository.root, configPath, config.integrity.configSignatureFile, options.publicKey!);
      process.stdout.write(`${ok ? 'PASS' : 'FAIL'} configuration signature\n`); return ok ? EXIT_CODES.PASS : EXIT_CODES.POLICY_FAILURE;
    }
    if (options.command === 'intelligence-import') {
      const result = await importVulnerabilityBundle(repository.root, options.bundle!, config.vulnerabilities.databaseFile, { requireSignature: config.offline.requireSignedIntelligenceBundles, ...(options.publicKey || config.offline.intelligencePublicKeyFile ? { publicKeyFile: options.publicKey ?? config.offline.intelligencePublicKeyFile } : {}) });
      await appendAuditEvent(repository.root, config.integrity.auditLogFile, 'intelligence.imported', { id: result.id, version: result.version, advisoryCount: result.advisoryCount });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return EXIT_CODES.PASS;
    }
    if (options.command === 'enterprise-diagnostics') {
      const checks = await runDiagnostics(repository.root, config);
      const ok = checks.every((item) => item.ok);
      const rendered = options.format === 'json' ? `${JSON.stringify({ ok, checks }, null, 2)}\n` : `${checks.map((item) => `${item.ok ? 'PASS' : 'FAIL'} ${item.id}: ${item.detail}`).join('\n')}\n`;
      process.stdout.write(rendered); return ok ? EXIT_CODES.PASS : EXIT_CODES.RUNTIME_FAILURE;
    }
    if (options.command === 'enterprise-backup') {
      const path = await createBackup(repository.root, ['.sentrycode/config.json', config.policy.directory, config.waivers.file, config.vulnerabilities.databaseFile, config.compliance.storeDirectory, config.integrity.auditLogFile], config.operations.backupDirectory);
      await appendAuditEvent(repository.root, config.integrity.auditLogFile, 'backup.created', { path });
      process.stdout.write(`Backup created: ${path}\n`); return EXIT_CODES.PASS;
    }
    if (options.command === 'enterprise-restore') {
      await restoreBackup(repository.root, options.backup!, { 'config.json': '.sentrycode/config.json', 'policies': config.policy.directory, 'waivers.json': config.waivers.file, 'vulnerability-db.json': config.vulnerabilities.databaseFile, 'compliance': config.compliance.storeDirectory, 'events.jsonl': config.integrity.auditLogFile });
      await appendAuditEvent(repository.root, config.integrity.auditLogFile, 'backup.restored', { path: options.backup! });
      process.stdout.write(`Backup restored: ${options.backup}\n`); return EXIT_CODES.PASS;
    }
    if (options.command === 'enterprise-retention') {
      const backups = await applyRetention(repository.root, config.operations.backupDirectory, config.operations.retentionDays);
      const evidence = await applyComplianceRetention(repository.root, config.compliance.storeDirectory, config.operations.retentionDays);
      await appendAuditEvent(repository.root, config.integrity.auditLogFile, 'retention.applied', { backupEntriesRemoved: backups.length, evidenceEntriesRemoved: evidence.length });
      process.stdout.write(`${JSON.stringify({ backupsRemoved: backups, evidenceEntriesRemoved: evidence }, null, 2)}\n`); return EXIT_CODES.PASS;
    }

    if (options.command === 'compliance-manifest' || options.command === 'compliance-health' || options.command === 'compliance-ready' || options.command === 'compliance-runs' || options.command === 'compliance-run' || options.command === 'compliance-serve') {
      const service = new SentryCodeComplianceService(repository.root, config.compliance.storeDirectory);
      if (options.command === 'compliance-serve') {
        const token = process.env[config.compliance.apiTokenEnv] ?? '';
        const running = await startComplianceServer(service, { host: config.compliance.listenHost, port: config.compliance.listenPort, ...(token ? { token } : {}) });
        process.stdout.write(`SentryCode Compliance API listening on ${running.host}:${running.port}\n`);
        await new Promise<void>(() => {});
        return EXIT_CODES.PASS;
      }
      let value: unknown;
      if (options.command === 'compliance-manifest') value = await service.manifest();
      else if (options.command === 'compliance-health') value = service.health();
      else if (options.command === 'compliance-ready') value = await service.readiness();
      else {
        const identity = resolveComplianceIdentity(config, options);
        if (options.command === 'compliance-runs') value = await service.listRuns(identity);
        else value = await service.getRun(identity, options.runId!);
      }
      if (options.format === 'json') process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
      else if (options.command === 'compliance-health') process.stdout.write('PASS SentryCode Compliance plugin health\n');
      else if (options.command === 'compliance-ready') {
        const readiness = value as Awaited<ReturnType<SentryCodeComplianceService['readiness']>>;
        process.stdout.write(`${readiness.ready ? 'PASS' : 'FAIL'} SentryCode Compliance plugin readiness\n${readiness.checks.map((item) => `${item.ok ? 'PASS' : 'FAIL'} ${item.id}: ${item.detail}`).join('\n')}\n`);
        if (!readiness.ready) return EXIT_CODES.RUNTIME_FAILURE;
      } else process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
      return EXIT_CODES.PASS;
    }

    if (options.command === 'services') {
      const services = await discoverServices(repository.root, config);
      const rendered = options.format === 'json'
        ? `${JSON.stringify({ schemaVersion: '1.0.0', services }, null, 2)}\n`
        : `${services.map((item) => `${item.name}\t${item.kind}\t${item.root || '.'}`).join('\n')}\n`;
      if (options.output) console.log(`Service inventory written: ${await writeOutput(repository.root, options.output, rendered)}`);
      else process.stdout.write(rendered);
      return EXIT_CODES.PASS;
    }

    if (options.command === 'provenance-verify') {
      const raw = JSON.parse(await readFile(resolve(repository.root, options.attestation), 'utf8')) as SignedAttestation;
      const ok = await verifyAttestation(raw, resolve(repository.root, options.publicKey));
      process.stdout.write(`${ok ? 'PASS' : 'FAIL'} provenance signature\n`);
      return ok ? EXIT_CODES.PASS : EXIT_CODES.POLICY_FAILURE;
    }

    if (options.command === 'provenance-attest') {
      const artifacts = await collectArtifacts(repository.root, options.artifact);
      const statement = buildStatement(repository, artifacts);
      const privateKey = options.key ? resolve(repository.root, options.key) : (config.provenance.signingPrivateKeyFile ? resolve(repository.root, config.provenance.signingPrivateKeyFile) : undefined);
      const attestation = await signStatement(statement, privateKey);
      const rendered = `${JSON.stringify(attestation, null, 2)}\n`;
      if (options.output) console.log(`Provenance attestation written: ${await writeOutput(repository.root, options.output, rendered)}`); else process.stdout.write(rendered);
      return EXIT_CODES.PASS;
    }

    if (options.command === 'sbom') {
      const snapshot = await discoverDependencies(repository.root);
      const components = snapshot.components.filter((item) => config.dependencies.includeDev || !item.dev);
      const document = options.format === 'spdx' ? spdxSbom(repository, components, snapshot.generatedAt) : cyclonedxSbom(repository, components, snapshot.generatedAt);
      const rendered = `${JSON.stringify(document, null, 2)}\n`;
      if (options.output) console.log(`SBOM written: ${await writeOutput(repository.root, options.output, rendered)}`);
      else process.stdout.write(rendered);
      return EXIT_CODES.PASS;
    }

    if (options.command === 'policy-validate') {
      try {
        const documents = await loadPolicyDocuments(repository.root, config.policy.directory, policyContext(repository.repository, config, options.service), new Date());
        const effective = resolvePolicy(config, documents);
        const rendered = options.format === 'json' ? `${JSON.stringify(effective, null, 2)}\n` : renderEffectivePolicy(effective);
        if (options.output) console.log(`Effective policy written: ${await writeOutput(repository.root, options.output, rendered)}`);
        else process.stdout.write(rendered);
        return EXIT_CODES.PASS;
      } catch (error) {
        console.error(`Configuration error: ${(error as Error).message}`);
        return EXIT_CODES.CONFIGURATION_FAILURE;
      }
    }

    const ciContext = detectCi(config);
    const plan = await buildIncrementalPlan({
      root: repository.root,
      repository: repository.repository,
      commitSha: repository.commitSha,
      config,
      ci: ciContext,
      ...(options.full !== undefined ? { forceFull: options.full } : {}),
      ...(options.base ? { baseRef: options.base } : {}),
      ...(options.head ? { headRef: options.head } : {})
    });
    let changedFiles = plan.changedFiles;
    if (options.service && plan.mode === 'incremental') {
      const services = await discoverServices(repository.root, config);
      const selected = services.find((item) => item.name === options.service || item.root === options.service);
      if (!selected) throw new Error(`Unknown service: ${options.service}`);
      if (selected.root) changedFiles = changedFiles.filter((file) => file === selected.root || file.startsWith(`${selected.root}/`));
    }
    const execution = {
      mode: plan.mode,
      ...(plan.baseRef ? { baseRef: plan.baseRef } : {}),
      ...(plan.headRef ? { headRef: plan.headRef } : {}),
      changedFiles,
      ...(options.service ? { service: options.service } : {}),
      ...((options.ci || ciContext.detected) ? { ci: ciContext } : {})
    } as const;
    const report = await runScan({
      repository,
      config,
      scanners: [new SecretsScanner(), new DependencyScanner(), new SastScanner(), new GitAssuranceScanner(), new ProvenanceScanner(), new AutomotiveScanner()],
      execution,
      ...(options.service ? { service: options.service } : {})
    });

    if (options.command === 'compliance-publish' || config.compliance.enabled) {
      const publication = await publishCompliance(repository.root, config, options, report);
      if (options.command === 'compliance-publish') {
        const rendered = options.format === 'json'
          ? `${JSON.stringify(publication, null, 2)}\n`
          : `SentryCode Compliance publication\nRun: ${publication.summary.runId}\nTenant: ${publication.summary.tenant}\nProject: ${publication.summary.project}\nDecision: ${publication.summary.decision}\nEvidence: ${publication.summary.evidenceCount}\n`;
        if (options.output) console.log(`Compliance publication written: ${await writeOutput(repository.root, options.output, rendered)}`);
        else process.stdout.write(rendered);
        return publication.summary.decision === 'FAIL' ? EXIT_CODES.POLICY_FAILURE : EXIT_CODES.PASS;
      }
    }

    if (options.command === 'release-check') {
      const release = buildReleaseDecision(report);
      report.evidence.push(release.evidence);
      report.policy.audit.push({
        event: 'release.decision',
        at: release.decision.evaluatedAt,
        policyFingerprint: release.decision.policyFingerprint,
        decision: release.decision.decision,
        reason: release.decision.reasons.join('; ')
      });
      const payload = { release: release.decision, report };
      const rendered = options.format === 'json'
        ? `${JSON.stringify(payload, null, 2)}\n`
        : options.format === 'sarif'
          ? renderSarif(report)
          : `${renderPolicyEvaluation(report)}\nRelease gate: ${release.decision.decision}\nRelease ID: ${release.decision.releaseId}\n`;
      if (options.output) console.log(`Release report written: ${await writeOutput(repository.root, options.output, rendered)}`);
      else process.stdout.write(rendered);
      if (config.ci.annotations && (options.ci || ciContext.detected)) process.stdout.write(renderCiAnnotations(report, ciContext));
      if (release.decision.decision !== 'FAIL' && !repository.isDirty && repository.commitSha) {
        await writeIncrementalCache(repository.root, config.incremental.cacheFile, { schemaVersion: 1, repository: repository.repository, lastSuccessfulCommit: repository.commitSha, updatedAt: report.completedAt });
      }
      return release.decision.decision === 'FAIL' ? EXIT_CODES.POLICY_FAILURE : EXIT_CODES.PASS;
    }

    const rendered = options.format === 'json' ? renderJson(report) : options.format === 'sarif' ? renderSarif(report) : (options.command === 'policy-evaluate' ? renderPolicyEvaluation(report) : `${renderConsole(report)}\n`);
    if (options.output) {
      if (options.format === 'json') { const written = await writeJsonReport(repository.root, options.output, report); console.log(`SentryCode report written: ${written}`); }
      else if (options.format === 'sarif') console.log(`SARIF report written: ${await writeOutput(repository.root, options.output, rendered)}`);
      else { console.error('--output requires --format json or sarif for scan/check/policy evaluate'); return EXIT_CODES.CONFIGURATION_FAILURE; }
    } else process.stdout.write(rendered);
    if (config.ci.annotations && (options.ci || ciContext.detected)) process.stdout.write(renderCiAnnotations(report, ciContext));
    if (report.policy.decision !== 'FAIL' && !repository.isDirty && repository.commitSha) {
      await writeIncrementalCache(repository.root, config.incremental.cacheFile, { schemaVersion: 1, repository: repository.repository, lastSuccessfulCommit: repository.commitSha, updatedAt: report.completedAt });
    }
    return report.policy.decision === 'FAIL' ? EXIT_CODES.POLICY_FAILURE : EXIT_CODES.PASS;
  } catch (error) {
    console.error(`Runtime failure: ${(error as Error).message}`);
    return EXIT_CODES.RUNTIME_FAILURE;
  }
}

process.exitCode = await main();
