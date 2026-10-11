import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { runScan } from '../src/core/engine.js';
import type { ScannerPlugin } from '../src/core/types.js';
import { buildPublication } from '../src/compliance/publication.js';

function success(id: string): ScannerPlugin {
  return {
    id,
    version: 'test',
    async scan() {
      return { scanner: id, findings: [], evidence: [], durationMs: 0 };
    }
  };
}

async function reportForFailure(message: string) {
  const root = await mkdtemp(join(tmpdir(), 'sc-failure-class-'));
  const config = structuredClone(DEFAULT_CONFIG);
  if (!config.policy.requiredScanners.includes('supply-chain')) {
    config.policy.requiredScanners.push('supply-chain');
  }
  const failing: ScannerPlugin = {
    id: 'supply-chain',
    version: 'test',
    async scan() {
      throw new Error(message);
    }
  };

  try {
    const report = await runScan({
      repository: { root, repository: 'repo', commitSha: 'abc', branch: 'main', isDirty: false },
      config,
      scanners: [success('secrets'), success('dependencies'), failing, success('sast'), success('git-assurance')],
      now: () => new Date('2026-10-10T12:00:00Z')
    });
    return structuredClone(report);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('runner startup failures are typed and emitted as scanner.failure evidence', async () => {
  const report = await reportForFailure('Supply-chain execution failed: SCANNER_LAUNCH_FAILED');
  const scanner = report.scanners.find((item) => item.scanner === 'supply-chain');
  assert.equal(scanner?.status, 'failed');
  assert.equal(scanner?.failure?.category, 'runner_startup');
  assert.equal(scanner?.failure?.code, 'SCANNER_LAUNCH_FAILED');

  const evidence = report.evidence.find((item) => item.type === 'scanner.failure');
  assert.equal(evidence?.metadata.category, 'runner_startup');
  assert.equal(evidence?.metadata.code, 'SCANNER_LAUNCH_FAILED');
  assert.equal(evidence?.findingIds.length, 0);
  assert.equal(report.policy.decision, 'FAIL');
});

test('scanner execution failures are distinct from vulnerability findings', async () => {
  const report = await reportForFailure('Supply-chain execution failed: SCANNER_EXECUTION_FAILED');
  const scanner = report.scanners.find((item) => item.scanner === 'supply-chain');
  assert.equal(scanner?.failure?.category, 'scanner_execution');
  assert.equal(scanner?.findings.length, 0);
  assert.equal(report.evidence.find((item) => item.type === 'scanner.failure')?.metadata.category, 'scanner_execution');
});

test('provisioning failures are typed separately', async () => {
  const report = await reportForFailure('Runner credential is unavailable: SENTRYCODE_RUNNER_TOKEN');
  const scanner = report.scanners.find((item) => item.scanner === 'supply-chain');
  assert.equal(scanner?.failure?.category, 'provisioning');
});

test('governed intelligence failures are typed separately', async () => {
  const report = await reportForFailure('Runner profile intelligence is stale: 200.0h > 120h');
  const scanner = report.scanners.find((item) => item.scanner === 'supply-chain');
  assert.equal(scanner?.failure?.category, 'intelligence');
});

test('coverage failure returned by a scanner is normalized into structured failure evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-failure-coverage-'));
  try {
    const config = structuredClone(DEFAULT_CONFIG);
    const scanner: ScannerPlugin = {
      id: 'supply-chain',
      version: 'test',
      async scan() {
        return {
          scanner: 'supply-chain',
          findings: [],
          evidence: [],
          durationMs: 1,
          status: 'failed',
          error: 'Dependency inventory coverage incomplete: 2 unresolved component(s)'
        };
      }
    };
    const report = await runScan({
      repository: { root, repository: 'repo', commitSha: 'abc', branch: 'main', isDirty: false },
      config,
      scanners: [success('secrets'), success('dependencies'), scanner, success('sast'), success('git-assurance')],
      now: () => new Date('2026-10-10T12:00:00Z')
    });
    assert.equal(report.scanners.find((item) => item.scanner === 'supply-chain')?.failure?.category, 'coverage');
    assert.equal(report.evidence.find((item) => item.type === 'scanner.failure')?.metadata.category, 'coverage');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Compliance publication carries scanner.failure evidence unchanged', async () => {
  const report = await reportForFailure('Supply-chain execution failed: SCANNER_TIMEOUT');
  const publication = buildPublication({ tenant: 'tenant-a', project: 'project-a' }, report, 'test');
  const failure = publication.evidence.evidence.find((item) => item.type === 'scanner.failure');
  assert.equal(failure?.metadata.category, 'scanner_execution');
  assert.equal(failure?.metadata.code, 'SCANNER_TIMEOUT');
  assert.equal(publication.report.scanners.find((item) => item.scanner === 'supply-chain')?.failure?.category, 'scanner_execution');
});

test('policy evidence summarizes scanner failure categories for UI/status surfaces', async () => {
  const report = await reportForFailure('Runner credential is unavailable: TOKEN');
  const policyEvidence = report.evidence.find((item) => item.type === 'policy.eval');
  assert.equal(policyEvidence?.metadata.scannerFailureCount, 1);
  assert.equal(policyEvidence?.metadata.scannerFailureCategories, 'provisioning');
});