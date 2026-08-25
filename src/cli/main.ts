#!/usr/bin/env node
import { stat } from 'node:fs/promises';
import { resolveRepository } from '../core/repository.js';
import { loadConfig } from '../config/load.js';
import { runScan } from '../core/engine.js';
import { SecretsScanner } from '../scanners/secrets/scanner.js';
import { renderConsole } from '../reporting/console.js';
import { renderJson, writeJsonReport } from '../reporting/json.js';
import { EXIT_CODES } from './exit-codes.js';

interface CliOptions {
  command: 'scan' | 'check';
  path: string;
  config?: string;
  format: 'console' | 'json';
  output?: string;
}

function usage(): string {
  return `QUILONS SentryCode\n\nUsage:\n  sentrycode scan [path] [--config FILE] [--format console|json] [--output FILE]\n  sentrycode check [path] [--config FILE] [--format console|json] [--output FILE]\n\nCommands:\n  scan   Scan a repository and evaluate policy.\n  check  Alias of scan for CI/policy-gate use.\n\nExit codes:\n  0 PASS/WARN\n  1 policy failure\n  2 scan/runtime failure\n  3 configuration/usage failure\n`;
}

function parseArgs(argv: string[]): CliOptions | 'help' {
  if (!argv.length || argv.includes('--help') || argv.includes('-h')) return 'help';
  const command = argv[0];
  if (command !== 'scan' && command !== 'check') throw new Error(`Unknown command: ${command ?? ''}`);
  let path = process.cwd();
  let config: string | undefined;
  let format: 'console' | 'json' = 'console';
  let output: string | undefined;
  let positionalUsed = false;

  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--config') config = argv[++i];
    else if (arg === '--format') {
      const value = argv[++i];
      if (value !== 'console' && value !== 'json') throw new Error('--format must be console or json');
      format = value;
    } else if (arg === '--output') output = argv[++i];
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else if (!positionalUsed) {
      path = arg;
      positionalUsed = true;
    } else throw new Error(`Unexpected argument: ${arg}`);
  }
  if ((argv.includes('--config') && !config) || (argv.includes('--output') && !output)) throw new Error('Option requires a value');
  return { command, path, format, ...(config ? { config } : {}), ...(output ? { output } : {}) };
}

async function main(): Promise<number> {
  let options: CliOptions | 'help';
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`Configuration error: ${(error as Error).message}\n`);
    console.error(usage());
    return EXIT_CODES.CONFIGURATION_FAILURE;
  }
  if (options === 'help') {
    console.log(usage());
    return EXIT_CODES.PASS;
  }

  try {
    await stat(options.path);
    const repository = await resolveRepository(options.path);
    let config;
    try {
      config = await loadConfig(repository.root, options.config);
    } catch (error) {
      console.error(`Configuration error: ${(error as Error).message}`);
      return EXIT_CODES.CONFIGURATION_FAILURE;
    }
    const report = await runScan({ repository, config, scanners: [new SecretsScanner()] });
    const rendered = options.format === 'json' ? renderJson(report) : `${renderConsole(report)}\n`;
    if (options.output) {
      if (options.format !== 'json') {
        console.error('--output currently requires --format json');
        return EXIT_CODES.CONFIGURATION_FAILURE;
      }
      const written = await writeJsonReport(repository.root, options.output, report);
      console.log(`SentryCode report written: ${written}`);
    } else {
      process.stdout.write(rendered);
    }
    return report.policy.decision === 'FAIL' ? EXIT_CODES.POLICY_FAILURE : EXIT_CODES.PASS;
  } catch (error) {
    console.error(`Runtime failure: ${(error as Error).message}`);
    return EXIT_CODES.RUNTIME_FAILURE;
  }
}

process.exitCode = await main();
