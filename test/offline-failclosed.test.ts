import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DependencyScanner } from '../src/scanners/dependencies/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('offline mode fails dependency scanner when vulnerability database is unavailable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-offline-'));
  await writeFile(join(root, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  const config = structuredClone(DEFAULT_CONFIG);
  config.offline.enabled = true;
  config.vulnerabilities.databaseFile = '.sentrycode/missing-db.json';
  await assert.rejects(() => new DependencyScanner().scan({ repository: { root, repository: 'demo', commitSha: null, branch: null, isDirty: false }, config, now: () => new Date('2026-08-25T00:00:00.000Z') }), /Offline vulnerability database is required/);
});
