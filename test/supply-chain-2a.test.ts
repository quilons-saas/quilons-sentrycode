import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { inventoryFromCycloneDx, findingsFromGrype } from '../src/scanners/supply-chain/adapters.js';
import { SupplyChainScanner, type SupplyChainRunner } from '../src/scanners/supply-chain/scanner.js';
import { sha256, type RunnerJobResponseV1 } from '../src/execution/contracts.js';

function runnerResponse(syft: unknown, grype: unknown): RunnerJobResponseV1 {
  const syftBytes = Buffer.from(JSON.stringify(syft));
  const grypeBytes = Buffer.from(JSON.stringify(grype));
  return {
    schemaVersion: 1,
    runId: 'replaced',
    scope: { tenant: 'tenant-a', project: 'project-a' },
    profileId: 'syft-grype',
    profileVersion: 'test-only',
    profileDigest: 'a'.repeat(64),
    rulesIdentity: 'syft:test;grype:test;grype-db:test',
    inputDigest: 'b'.repeat(64),
    outcome: 'completed',
    cleanupConfirmed: true,
    artifacts: [
      { name: 'syft.cdx.json', sha256: sha256(syftBytes), bytes: syftBytes.length, contentBase64: syftBytes.toString('base64') },
      { name: 'grype.json', sha256: sha256(grypeBytes), bytes: grypeBytes.length, contentBase64: grypeBytes.toString('base64') }
    ],
    steps: [
      { stepId: 'syft', imageRef: `example/syft@sha256:${'c'.repeat(64)}`, imageDigest: 'c'.repeat(64), exitCode: 0, outcome: 'completed' },
      { stepId: 'grype', imageRef: `example/grype@sha256:${'d'.repeat(64)}`, imageDigest: 'd'.repeat(64), exitCode: 0, outcome: 'completed' }
    ],
    events: []
  };
}

test('Syft inventory classifies direct, transitive, OS and unknown relationships without inventing directness', () => {
  const parsed = inventoryFromCycloneDx({
    bomFormat: 'CycloneDX', specVersion: '1.5',
    metadata: { component: { 'bom-ref': 'root' } },
    dependencies: [
      { ref: 'root', dependsOn: ['pkg:npm/direct@1.0.0'] },
      { ref: 'pkg:npm/direct@1.0.0', dependsOn: ['pkg:npm/transitive@2.0.0'] }
    ],
    components: [
      { name: 'direct', version: '1.0.0', purl: 'pkg:npm/direct@1.0.0', 'bom-ref': 'pkg:npm/direct@1.0.0' },
      { name: 'transitive', version: '2.0.0', purl: 'pkg:npm/transitive@2.0.0', 'bom-ref': 'pkg:npm/transitive@2.0.0' },
      { name: 'openssl', version: '3.0-r1', purl: 'pkg:apk/openssl@3.0-r1' },
      { name: 'native', version: '1.2.3', purl: 'pkg:vcpkg/native@1.2.3' }
    ]
  });
  assert.equal(parsed.components.find((item) => item.name === 'direct')?.relationship, 'direct');
  assert.equal(parsed.components.find((item) => item.name === 'transitive')?.relationship, 'transitive');
  assert.equal(parsed.components.find((item) => item.name === 'openssl')?.relationship, 'os');
  assert.equal(parsed.components.find((item) => item.name === 'native')?.relationship, 'unknown');
  assert.deepEqual(parsed.relationshipCoverage, { direct: 1, transitive: 1, os: 1, unknown: 1, graphAvailable: true });
});

test('Grype duplicate observations deduplicate while retaining aliases, locations and fixes', () => {
  const base = {
    vulnerability: { id: 'CVE-2026-0001', severity: 'High', fix: { state: 'fixed', versions: ['2.0.0'] } },
    artifact: { name: 'demo', version: '1.0.0', purl: 'pkg:npm/demo@1.0.0' }
  };
  const findings = findingsFromGrype({ matches: [
    { ...base, relatedVulnerabilities: [{ id: 'GHSA-one' }], artifact: { ...base.artifact, locations: [{ path: '/a/package-lock.json' }] } },
    { ...base, vulnerability: { ...base.vulnerability, fix: { state: 'fixed', versions: ['2.0.1'] } }, relatedVulnerabilities: [{ id: 'GHSA-two' }], artifact: { ...base.artifact, locations: [{ path: '/b/package-lock.json' }] } }
  ] }, '2026-10-07T00:00:00.000Z');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]?.fixedVersions, ['2.0.0', '2.0.1']);
  assert.equal(findings[0]?.finding.metadata?.aliases, 'GHSA-one,GHSA-two');
  assert.equal(findings[0]?.finding.metadata?.locations, '/a/package-lock.json,/b/package-lock.json');
});

test('managed supply-chain coverage fails closed when package identity remains unresolved', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-2a-coverage-'));
  try {
    await writeFile(join(root, 'README.md'), 'fixture');
    const config = structuredClone(DEFAULT_CONFIG);
    config.execution.runner.enabled = true;
    config.execution.runner.tenant = 'tenant-a';
    config.execution.runner.project = 'project-a';
    const result = runnerResponse(
      { bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'unknown', version: '1.0.0' }] },
      { matches: [] }
    );
    const runner: SupplyChainRunner = { async runRepositoryProfile(args) { result.runId = args.runId; return result; } };
    const scan = await new SupplyChainScanner(runner).scan({ repository: { root, repository: 'repo', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-10-07T00:00:00Z') });
    assert.equal(scan.status, 'failed');
    assert.match(scan.error ?? '', /coverage incomplete/);
    assert.equal(scan.findings[0]?.type, 'coverage');
    assert.equal(scan.evidence[0]?.metadata.coverageComplete, false);
  } finally { await rm(root, { recursive: true, force: true }); }
});
