import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { SupplyChainScanner, type SupplyChainRunner } from '../src/scanners/supply-chain/scanner.js';
import { DependencyScanner } from '../src/scanners/dependencies/scanner.js';
import { sha256, type RunnerJobResponseV1 } from '../src/execution/contracts.js';

function response(syft: unknown, grype: unknown): RunnerJobResponseV1 {
  const syftBytes = Buffer.from(JSON.stringify(syft));
  const grypeBytes = Buffer.from(JSON.stringify(grype));
  return {
    schemaVersion: 1,
    runId: 'ignored-by-injected-runner',
    scope: { tenant: 'tenant-a', project: 'project-a' },
    profileId: 'syft-grype', profileDigest: 'c'.repeat(64), rulesIdentity: 'grype-db:test', inputDigest: 'd'.repeat(64), outcome: 'completed', cleanupConfirmed: true,
    artifacts: [
      { name: 'syft.cdx.json', bytes: syftBytes.length, sha256: sha256(syftBytes), contentBase64: syftBytes.toString('base64') },
      { name: 'grype.json', bytes: grypeBytes.length, sha256: sha256(grypeBytes), contentBase64: grypeBytes.toString('base64') }
    ],
    steps: [
      { stepId: 'syft', imageRef: `ghcr.io/anchore/syft@sha256:${'a'.repeat(64)}`, imageDigest: 'a'.repeat(64), exitCode: 0, outcome: 'completed' },
      { stepId: 'grype', imageRef: `ghcr.io/anchore/grype@sha256:${'b'.repeat(64)}`, imageDigest: 'b'.repeat(64), exitCode: 1, outcome: 'completed' }
    ],
    events: []
  };
}

test('managed supply-chain path consumes runner artifacts and records immutable provenance', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-managed-'));
  try {
    await writeFile(join(root, 'package.json'), '{"name":"fixture","version":"1.0.0"}');
    const config = structuredClone(DEFAULT_CONFIG);
    config.execution.runner.enabled = true;
    config.execution.runner.tenant = 'tenant-a'; config.execution.runner.project = 'project-a';
    const runner: SupplyChainRunner = {
      async runRepositoryProfile(args) {
        const result = response(
          { bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }] },
          { matches: [{ vulnerability: { id: 'CVE-TEST-1', severity: 'High', fix: { versions: ['4.17.21'] } }, artifact: { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' } }] }
        );
        result.runId = args.runId;
        return result;
      }
    };
    const scan = await new SupplyChainScanner(runner).scan({ repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-10-06T00:00:00Z') });
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0]?.ruleId, 'CVE-TEST-1');
    assert.match(String(scan.evidence[0]?.metadata.imageIdentities), /@sha256:/);
    assert.equal(scan.evidence[0]?.metadata.cleanupConfirmed, true);
    assert.equal(scan.evidence[0]?.metadata.rulesIdentity, 'grype-db:test');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('managed supply-chain path fails closed on runner execution failure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-managed-fail-'));
  try {
    await writeFile(join(root, 'a.txt'), 'a');
    const config = structuredClone(DEFAULT_CONFIG); config.execution.runner.enabled = true; config.execution.runner.tenant = 'tenant-a'; config.execution.runner.project = 'project-a';
    const failed = response({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }, { matches: [] }); failed.outcome = 'timeout'; failed.errorCode = 'SCANNER_TIMEOUT'; failed.cleanupConfirmed = true;
    const runner: SupplyChainRunner = { async runRepositoryProfile(args) { failed.runId = args.runId; return failed; } };
    await assert.rejects(() => new SupplyChainScanner(runner).scan({ repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date() }), /SCANNER_TIMEOUT/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('managed supply-chain path rejects tampered runner report bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-managed-tamper-'));
  try {
    await writeFile(join(root, 'a.txt'), 'a');
    const config = structuredClone(DEFAULT_CONFIG); config.execution.runner.enabled = true; config.execution.runner.tenant = 'tenant-a'; config.execution.runner.project = 'project-a';
    const result = response({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }, { matches: [] }); result.artifacts[0]!.sha256 = '0'.repeat(64);
    const runner: SupplyChainRunner = { async runRepositoryProfile(args) { result.runId = args.runId; return result; } };
    await assert.rejects(() => new SupplyChainScanner(runner).scan({ repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date() }), /integrity failure/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('managed Grype authority suppresses duplicate legacy vulnerability database matches while retaining dependency policy', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-authority-'));
  try {
    await mkdir(join(root, '.sentrycode'));
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app', version: '1.0.0' }, 'node_modules/demo': { version: '1.5.0', license: 'AGPL-3.0', resolved: 'https://registry.npmjs.org/demo/-/demo-1.5.0.tgz' } } }));
    await writeFile(join(root, '.sentrycode/vulnerability-db.json'), JSON.stringify({ schemaVersion: 1, advisories: [{ id: 'CVE-LEGACY', ecosystem: 'npm', package: 'demo', affected: '<2.0.0', severity: 'critical' }] }));
    const config = structuredClone(DEFAULT_CONFIG); config.execution.runner.enabled = true;
    const scan = await new DependencyScanner().scan({ repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-10-06T00:00:00Z') });
    assert.equal(scan.findings.some((item) => item.ruleId === 'CVE-LEGACY'), false);
    assert.equal(scan.findings.some((item) => item.ruleId === 'license.denied'), true);
  } finally { await rm(root, { recursive: true, force: true }); }
});
