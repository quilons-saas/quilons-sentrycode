import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyComplianceRetention } from '../src/enterprise/backup.js';

test('compliance retention removes expired runs but keeps recent runs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-retention-'));
  const oldRun = join(root, '.sentrycode/compliance/scope-a/runs/old');
  const newRun = join(root, '.sentrycode/compliance/scope-a/runs/new');
  await mkdir(oldRun, { recursive: true }); await mkdir(newRun, { recursive: true });
  await writeFile(join(oldRun, 'summary.json'), JSON.stringify({ completedAt: '2020-01-01T00:00:00.000Z' }));
  await writeFile(join(newRun, 'summary.json'), JSON.stringify({ completedAt: new Date().toISOString() }));
  const removed = await applyComplianceRetention(root, '.sentrycode/compliance', 365);
  assert.deepEqual(removed, ['scope-a/old']);
  await assert.rejects(() => stat(oldRun));
  assert.equal((await stat(newRun)).isDirectory(), true);
});
