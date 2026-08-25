import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/utils/hash.js';
import { importVulnerabilityBundle } from '../src/enterprise/intelligence.js';

test('imports digest-verified offline vulnerability bundle', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-intel-'));
  const database = { schemaVersion: 1 as const, updatedAt: '2026-08-25T00:00:00.000Z', advisories: [{ id: 'TEST-1', ecosystem: 'npm' as const, package: 'demo', affected: '<2.0.0', severity: 'high' as const }] };
  const bundle = { schemaVersion: 1 as const, id: 'bundle-1', version: '2026.08.25', createdAt: '2026-08-25T00:00:00.000Z', database, databaseSha256: sha256(JSON.stringify(database)) };
  await writeFile(join(root, 'bundle.json'), JSON.stringify(bundle));
  const result = await importVulnerabilityBundle(root, 'bundle.json', '.sentrycode/vulnerability-db.json', { requireSignature: false });
  assert.equal(result.advisoryCount, 1);
  const stored = JSON.parse(await readFile(join(root, '.sentrycode/vulnerability-db.json'), 'utf8')) as typeof database;
  assert.equal(stored.advisories[0]?.id, 'TEST-1');
});
