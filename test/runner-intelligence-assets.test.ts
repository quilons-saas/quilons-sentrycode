import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RunnerProfileRegistry } from '../src/execution/profile-registry.js';
import { sha256 } from '../src/execution/contracts.js';

function setDigest(assets: Array<{ path: string; sha256: string }>): string {
  return sha256([...assets].sort((a, b) => a.path.localeCompare(b.path)).map((asset) => `${asset.path}\0${asset.sha256}\0`).join(''));
}

test('profile registry binds governed intelligence to the complete declared multi-file database snapshot', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-intel-set-'));
  const profile = join(root, 'syft-grype');
  try {
    await mkdir(join(profile, 'db'), { recursive: true });
    const a = Buffer.from('db-part-a'); const b = Buffer.from('db-part-b');
    await writeFile(join(profile, 'db/a.bin'), a); await writeFile(join(profile, 'db/b.bin'), b);
    const assets = [{ path: 'db/a.bin', sha256: sha256(a) }, { path: 'db/b.bin', sha256: sha256(b) }];
    await writeFile(join(profile, 'profile.json'), JSON.stringify({
      schemaVersion: 1, id: 'syft-grype', version: 'test', rulesIdentity: 'grype:test',
      steps: [{ id: 'scan', imageRef: `example/scanner@sha256:${'a'.repeat(64)}`, args: [], acceptedExitCodes: [0], timeoutMs: 1000, outputs: [] }],
      assets,
      intelligence: { provider: 'grype', id: 'db-test', schema: 'v6', builtAt: '2026-10-06T00:00:00Z', importedAt: '2026-10-06T01:00:00Z', assetPaths: ['db/b.bin', 'db/a.bin'], sha256: setDigest(assets), maxAgeHours: 120, sources: ['anchore'] }
    }));
    const loaded = await new RunnerProfileRegistry(root, () => new Date('2026-10-07T00:00:00Z')).load('syft-grype');
    assert.deepEqual(loaded.manifest.intelligence?.assetPaths, ['db/a.bin', 'db/b.bin']);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('profile registry rejects intelligence imported before its upstream build time', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-intel-time-'));
  const profile = join(root, 'syft-grype');
  try {
    await mkdir(profile, { recursive: true });
    const db = Buffer.from('db');
    await writeFile(join(profile, 'db.bin'), db);
    await writeFile(join(profile, 'profile.json'), JSON.stringify({
      schemaVersion: 1, id: 'syft-grype', version: 'test', rulesIdentity: 'grype:test',
      steps: [{ id: 'scan', imageRef: `example/scanner@sha256:${'a'.repeat(64)}`, args: [], acceptedExitCodes: [0], timeoutMs: 1000, outputs: [] }],
      assets: [{ path: 'db.bin', sha256: sha256(db) }],
      intelligence: { provider: 'grype', id: 'db-test', schema: 'v6', builtAt: '2026-10-06T02:00:00Z', importedAt: '2026-10-06T01:00:00Z', path: 'db.bin', sha256: sha256(db), maxAgeHours: 120, sources: ['anchore'] }
    }));
    await assert.rejects(() => new RunnerProfileRegistry(root, () => new Date('2026-10-07T00:00:00Z')).load('syft-grype'), /predates/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
