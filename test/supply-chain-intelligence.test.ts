import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { inventoryFromCycloneDx, findingsFromGrype } from '../src/scanners/supply-chain/adapters.js';
import { RunnerProfileRegistry } from '../src/execution/profile-registry.js';
import { sha256 } from '../src/execution/contracts.js';

test('governed Syft inventory retains direct/transitive OS packages and unresolved identities', () => {
  const inventory = inventoryFromCycloneDx({
    bomFormat: 'CycloneDX', specVersion: '1.5',
    metadata: { component: { 'bom-ref': 'root' } },
    dependencies: [{ ref: 'root', dependsOn: ['npm-a', 'deb-a'] }],
    components: [
      { name: 'a', version: '1.0.0', purl: 'pkg:npm/a@1.0.0', 'bom-ref': 'npm-a' },
      { name: 'b', version: '2.0.0', purl: 'pkg:npm/b@2.0.0', 'bom-ref': 'npm-b' },
      { name: 'openssl', version: '3.0.0', purl: 'pkg:deb/openssl@3.0.0?distro=debian-12', 'bom-ref': 'deb-a' },
      { name: 'mystery', version: '1', purl: 'pkg:generic/mystery@1' },
      { name: 'no-purl', version: '1' }
    ]
  });
  assert.equal(inventory.components.find((item) => item.name === 'a')?.direct, true);
  assert.equal(inventory.components.find((item) => item.name === 'b')?.direct, false);
  assert.equal(inventory.components.find((item) => item.name === 'openssl')?.ecosystem, 'deb');
  assert.deepEqual(inventory.unresolved.map((item) => item.reason).sort(), ['missing-purl', 'unsupported-ecosystem']);
});

test('Grype normalization retains native severity, aliases, CVSS, fix state and locations', () => {
  const result = findingsFromGrype({ matches: [{
    vulnerability: { id: 'CVE-2026-1', severity: 'Critical', description: 'bad', dataSource: 'https://example.invalid/cve', fix: { state: 'fixed', versions: ['2.0.0'] }, cvss: [{ vector: 'CVSS:3.1/AV:N', metrics: { baseScore: 9.8 } }] },
    relatedVulnerabilities: [{ id: 'GHSA-test' }],
    artifact: { name: 'demo', version: '1.0.0', purl: 'pkg:npm/demo@1.0.0', locations: [{ path: '/input/package-lock.json' }] }
  }] }, '2026-10-06T00:00:00.000Z');
  const first = result[0];
  assert.ok(first);
  assert.equal(first.finding.severity, 'critical');
  const metadata = first.finding.metadata;
  assert.ok(metadata);
  assert.equal(metadata.aliases, 'GHSA-test');
  assert.equal(metadata.cvssBaseScore, 9.8);
  assert.equal(metadata.fixState, 'fixed');
  assert.equal(metadata.locations, '/input/package-lock.json');
});

async function intelligenceProfile(builtAt: string): Promise<{ root: string; profile: string }> {
  const root = await mkdtemp(join(tmpdir(), 'sc-intel-profile-'));
  const profile = join(root, 'syft-grype');
  await mkdir(profile);
  const db = Buffer.from('governed-grype-database');
  await writeFile(join(profile, 'vulnerability.db'), db);
  await writeFile(join(profile, 'profile.json'), JSON.stringify({
    schemaVersion: 1, id: 'syft-grype', version: 'syft-1.54.0_grype-0.120.0', rulesIdentity: 'grype-db:test',
    steps: [
      { id: 'syft', imageRef: `docker.io/anchore/syft@sha256:${'a'.repeat(64)}`, args: ['dir:/input', '-o', 'cyclonedx-json=/output/syft.cdx.json'], acceptedExitCodes: [0], timeoutMs: 10000, outputs: ['syft.cdx.json'] },
      { id: 'grype', imageRef: `docker.io/anchore/grype@sha256:${'b'.repeat(64)}`, args: ['sbom:/output/syft.cdx.json', '-o', 'json', '--file', '/output/grype.json'], acceptedExitCodes: [0], timeoutMs: 10000, outputs: ['grype.json'], environment: { GRYPE_DB_CACHE_DIR: '/profile/grype-db', GRYPE_DB_AUTO_UPDATE: 'false', GRYPE_CHECK_FOR_APP_UPDATE: 'false' } }
    ],
    assets: [{ path: 'vulnerability.db', sha256: sha256(db) }],
    intelligence: { provider: 'grype-db', id: 'db-test', schema: 'v6', builtAt, importedAt: '2026-10-06T00:30:00Z', path: 'vulnerability.db', sha256: sha256(db), maxAgeHours: 120, sources: ['anchore-grype-db'] }
  }));
  return { root, profile };
}

test('profile registry accepts governed intelligence identity and fixed scanner environment', async () => {
  const fixture = await intelligenceProfile('2026-10-05T00:00:00Z');
  try {
    const loaded = await new RunnerProfileRegistry(fixture.root, () => new Date('2026-10-06T01:00:00Z')).load('syft-grype');
    assert.equal(loaded.manifest.intelligence?.schema, 'v6');
    assert.equal(loaded.manifest.steps[1]?.environment?.GRYPE_DB_AUTO_UPDATE, 'false');
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test('profile registry fails closed when governed vulnerability intelligence is stale', async () => {
  const fixture = await intelligenceProfile('2026-09-20T00:00:00Z');
  try {
    await assert.rejects(() => new RunnerProfileRegistry(fixture.root, () => new Date('2026-10-06T01:00:00Z')).load('syft-grype'), /intelligence is stale/);
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});


test('profile registry rejects undeclared files in the immutable scanner profile', async () => {
  const fixture = await intelligenceProfile('2026-10-05T00:00:00Z');
  try {
    await writeFile(join(fixture.profile, 'untracked.db'), 'not-declared');
    await assert.rejects(
      () => new RunnerProfileRegistry(fixture.root, () => new Date('2026-10-06T01:00:00Z')).load('syft-grype'),
      /undeclared file/
    );
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});
