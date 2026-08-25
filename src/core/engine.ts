import { randomUUID } from 'node:crypto';
import type { ScanReport, ScannerPlugin, SentryCodeConfig } from './types.js';
import type { RepositoryContext } from './types.js';
import { evaluatePolicy } from '../policy/evaluate.js';
import { loadWaivers } from '../policy/waivers.js';

export async function runScan(args: {
  repository: RepositoryContext;
  config: SentryCodeConfig;
  scanners: ScannerPlugin[];
  now?: () => Date;
}): Promise<ScanReport> {
  const now = args.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const scannerResults = [];
  for (const scanner of args.scanners) {
    scannerResults.push(await scanner.scan({ repository: args.repository, config: args.config, now }));
  }
  const waivers = await loadWaivers(args.repository.root, args.config.waiversFile);
  const policy = evaluatePolicy(args.config, scannerResults, waivers, now());
  const completedAt = now().toISOString();
  return {
    schemaVersion: '1.0.0',
    runId: randomUUID(),
    startedAt,
    completedAt,
    repository: args.repository,
    scanners: scannerResults,
    policy,
    evidence: scannerResults.flatMap((result) => result.evidence)
  };
}
