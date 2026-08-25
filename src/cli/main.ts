#!/usr/bin/env node
import { mkdir, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { resolveRepository } from '../core/repository.js';
import { loadConfig } from '../config/load.js';
import { runScan } from '../core/engine.js';
import { SecretsScanner } from '../scanners/secrets/scanner.js';
import { DependencyScanner } from '../scanners/dependencies/scanner.js';
import { discoverDependencies } from '../dependencies/discover.js';
import { dependencySnapshotAtRef, diffDependencies } from '../dependencies/diff.js';
import { cyclonedxSbom, spdxSbom } from '../sbom/generate.js';
import { renderConsole } from '../reporting/console.js';
import { renderJson, writeJsonReport } from '../reporting/json.js';
import { loadPolicyDocuments } from '../policy/documents.js';
import { resolvePolicy } from '../policy/resolve.js';
import { buildReleaseDecision } from '../policy/release.js';
import { EXIT_CODES } from './exit-codes.js';
import type { PolicyContext, ScanReport } from '../core/types.js';

interface CommonOptions { path: string; config?: string; output?: string; service?: string; }
interface ScanOptions extends CommonOptions { command: 'scan' | 'check'; format: 'console' | 'json'; }
interface SbomOptions extends CommonOptions { command: 'sbom'; format: 'cyclonedx' | 'spdx'; }
interface DiffOptions extends CommonOptions { command: 'dependencies-diff'; base: string; head: string; format: 'console' | 'json'; }
interface PolicyOptions extends CommonOptions { command: 'policy-validate' | 'policy-evaluate'; format: 'console' | 'json'; }
interface ReleaseOptions extends CommonOptions { command: 'release-check'; format: 'console' | 'json'; }
type CliOptions = ScanOptions | SbomOptions | DiffOptions | PolicyOptions | ReleaseOptions;

function usage(): string {
  return `QUILONS SentryCode

Usage:
  sentrycode scan [path] [--config FILE] [--service NAME] [--format console|json] [--output FILE]
  sentrycode check [path] [--config FILE] [--service NAME] [--format console|json] [--output FILE]
  sentrycode sbom [path] [--config FILE] [--format cyclonedx|spdx] [--output FILE]
  sentrycode dependencies diff [path] --base REF [--head REF] [--format console|json] [--output FILE]
  sentrycode policy validate [path] [--config FILE] [--service NAME] [--format console|json]
  sentrycode policy evaluate [path] [--config FILE] [--service NAME] [--format console|json] [--output FILE]
  sentrycode release check [path] [--config FILE] [--service NAME] [--format console|json] [--output FILE]

Commands:
  scan               Scan repository and evaluate policy.
  check              Alias of scan for CI/policy-gate use.
  sbom               Generate CycloneDX 1.5 or SPDX 2.3 SBOM.
  dependencies diff  Compare dependency state between Git refs.
  policy validate    Validate and resolve hierarchical policy documents.
  policy evaluate    Run scanners and show the effective policy decision.
  release check      Enforce the release gate and emit release.gate evidence.

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
  else if (argv[0] === 'scan' || argv[0] === 'check' || argv[0] === 'sbom') command = argv[0];
  else throw new Error(`Unknown command: ${argv.slice(0, 2).join(' ')}`);

  let path = process.cwd();
  let config: string | undefined;
  let output: string | undefined;
  let service: string | undefined;
  let base: string | undefined;
  let head = 'HEAD';
  let positionalUsed = false;
  let scanFormat: 'console' | 'json' = 'console';
  let sbomFormat: 'cyclonedx' | 'spdx' = 'cyclonedx';

  for (let i = offset; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--config') { config = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--output') { output = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--service') { service = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--base') { base = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--head') { head = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--format') {
      const value = requireValue(argv, i, arg); i += 1;
      if (command === 'sbom') {
        if (value !== 'cyclonedx' && value !== 'spdx') throw new Error('--format for sbom must be cyclonedx or spdx');
        sbomFormat = value;
      } else {
        if (value !== 'console' && value !== 'json') throw new Error('--format must be console or json');
        scanFormat = value;
      }
    } else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else if (!positionalUsed) { path = arg; positionalUsed = true; }
    else throw new Error(`Unexpected argument: ${arg}`);
  }

  const common = { path, ...(config ? { config } : {}), ...(output ? { output } : {}), ...(service ? { service } : {}) };
  if (command === 'dependencies-diff') {
    if (!base) throw new Error('dependencies diff requires --base REF');
    return { command, ...common, base, head, format: scanFormat };
  }
  if (command === 'sbom') return { command, ...common, format: sbomFormat };
  if (command === 'policy-validate' || command === 'policy-evaluate' || command === 'release-check') {
    return { command, ...common, format: scanFormat };
  }
  return { command, ...common, format: scanFormat };
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

    const report = await runScan({
      repository,
      config,
      scanners: [new SecretsScanner(), new DependencyScanner()],
      ...(options.service ? { service: options.service } : {})
    });

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
        : `${renderPolicyEvaluation(report)}\nRelease gate: ${release.decision.decision}\nRelease ID: ${release.decision.releaseId}\n`;
      if (options.output) console.log(`Release report written: ${await writeOutput(repository.root, options.output, rendered)}`);
      else process.stdout.write(rendered);
      return release.decision.decision === 'FAIL' ? EXIT_CODES.POLICY_FAILURE : EXIT_CODES.PASS;
    }

    const rendered = options.format === 'json' ? renderJson(report) : (options.command === 'policy-evaluate' ? renderPolicyEvaluation(report) : `${renderConsole(report)}\n`);
    if (options.output) {
      if (options.format !== 'json') {
        console.error('--output currently requires --format json for scan/check/policy evaluate');
        return EXIT_CODES.CONFIGURATION_FAILURE;
      }
      const written = await writeJsonReport(repository.root, options.output, report);
      console.log(`SentryCode report written: ${written}`);
    } else process.stdout.write(rendered);
    return report.policy.decision === 'FAIL' ? EXIT_CODES.POLICY_FAILURE : EXIT_CODES.PASS;
  } catch (error) {
    console.error(`Runtime failure: ${(error as Error).message}`);
    return EXIT_CODES.RUNTIME_FAILURE;
  }
}

process.exitCode = await main();
