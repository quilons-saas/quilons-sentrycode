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
import { EXIT_CODES } from './exit-codes.js';

interface ScanOptions { command: 'scan' | 'check'; path: string; config?: string; format: 'console' | 'json'; output?: string; }
interface SbomOptions { command: 'sbom'; path: string; config?: string; format: 'cyclonedx' | 'spdx'; output?: string; }
interface DiffOptions { command: 'dependencies-diff'; path: string; base: string; head: string; format: 'console' | 'json'; output?: string; }
type CliOptions = ScanOptions | SbomOptions | DiffOptions;

function usage(): string {
  return `QUILONS SentryCode\n\nUsage:\n  sentrycode scan [path] [--config FILE] [--format console|json] [--output FILE]\n  sentrycode check [path] [--config FILE] [--format console|json] [--output FILE]\n  sentrycode sbom [path] [--config FILE] [--format cyclonedx|spdx] [--output FILE]\n  sentrycode dependencies diff [path] --base REF [--head REF] [--format console|json] [--output FILE]\n\nCommands:\n  scan               Scan repository and evaluate policy.\n  check              Alias of scan for CI/policy-gate use.\n  sbom               Generate CycloneDX 1.5 or SPDX 2.3 SBOM.\n  dependencies diff  Compare dependency state between Git refs.\n\nExit codes:\n  0 PASS/WARN/success\n  1 policy failure\n  2 scan/runtime failure\n  3 configuration/usage failure\n`;
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
  else if (argv[0] === 'scan' || argv[0] === 'check' || argv[0] === 'sbom') command = argv[0];
  else throw new Error(`Unknown command: ${argv.slice(0, 2).join(' ')}`);

  let path = process.cwd();
  let config: string | undefined;
  let output: string | undefined;
  let base: string | undefined;
  let head = 'HEAD';
  let positionalUsed = false;
  let scanFormat: 'console' | 'json' = 'console';
  let sbomFormat: 'cyclonedx' | 'spdx' = 'cyclonedx';

  for (let i = offset; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--config') { config = requireValue(argv, i, arg); i += 1; }
    else if (arg === '--output') { output = requireValue(argv, i, arg); i += 1; }
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

  if (command === 'dependencies-diff') {
    if (!base) throw new Error('dependencies diff requires --base REF');
    return { command, path, base, head, format: scanFormat, ...(output ? { output } : {}) };
  }
  if (command === 'sbom') return { command, path, format: sbomFormat, ...(config ? { config } : {}), ...(output ? { output } : {}) };
  return { command, path, format: scanFormat, ...(config ? { config } : {}), ...(output ? { output } : {}) };
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

    const report = await runScan({ repository, config, scanners: [new SecretsScanner(), new DependencyScanner()] });
    const rendered = options.format === 'json' ? renderJson(report) : `${renderConsole(report)}\n`;
    if (options.output) {
      if (options.format !== 'json') { console.error('--output currently requires --format json'); return EXIT_CODES.CONFIGURATION_FAILURE; }
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
