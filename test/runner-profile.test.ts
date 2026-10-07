import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RunnerProfileRegistry } from '../src/execution/profile-registry.js';
import { sha256 } from '../src/execution/contracts.js';

async function profileFixture(): Promise<{ root: string; profile: string; asset: string }> {
  const root = await mkdtemp(join(tmpdir(), 'sc-profile-'));
  const profile = join(root, 'syft-grype');
  await mkdir(profile);
  const asset = Buffer.from('offline-database');
  await writeFile(join(profile, 'grype.db'), asset);
  const digestA = 'a'.repeat(64), digestB = 'b'.repeat(64);
  await writeFile(join(profile, 'profile.json'), JSON.stringify({
    schemaVersion: 1,
    id: 'syft-grype',
    version: 'test-only',
    rulesIdentity: 'rules:test',
    steps: [
      { id: 'syft', imageRef: `ghcr.io/anchore/syft@sha256:${digestA}`, args: ['dir:/input', '-o', 'cyclonedx-json=/output/syft.cdx.json'], acceptedExitCodes: [0], timeoutMs: 10000, outputs: ['syft.cdx.json'] },
      { id: 'grype', imageRef: `ghcr.io/anchore/grype@sha256:${digestB}`, args: ['sbom:/output/syft.cdx.json', '-o', 'json', '--file', '/output/grype.json'], acceptedExitCodes: [0, 1], timeoutMs: 10000, outputs: ['grype.json'] }
    ],
    assets: [{ path: 'grype.db', sha256: sha256(asset) }]
  }));
  return { root, profile, asset: join(profile, 'grype.db') };
}

test('profile registry verifies immutable images and declared assets', async () => {
  const fixture = await profileFixture();
  try {
    const loaded = await new RunnerProfileRegistry(fixture.root).load('syft-grype');
    assert.equal(loaded.manifest.steps.length, 2);
    assert.equal(loaded.manifest.steps[1]?.acceptedExitCodes.includes(1), true);
    assert.match(loaded.profileDigest, /^[a-f0-9]{64}$/);
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test('profile registry fails closed on profile asset tampering', async () => {
  const fixture = await profileFixture();
  try {
    await writeFile(fixture.asset, 'tampered');
    await assert.rejects(() => new RunnerProfileRegistry(fixture.root).load('syft-grype'), /asset hash mismatch/);
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test('profile registry rejects mutable image tags', async () => {
  const fixture = await profileFixture();
  try {
    const path = join(fixture.profile, 'profile.json');
    const value = JSON.parse(await (await import('node:fs/promises')).readFile(path, 'utf8')) as any;
    value.steps[0].imageRef = 'ghcr.io/anchore/syft:latest';
    await writeFile(path, JSON.stringify(value));
    await assert.rejects(() => new RunnerProfileRegistry(fixture.root).load('syft-grype'), /immutable by digest/);
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});
