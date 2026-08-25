import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { createBackup, restoreBackup } from '../src/enterprise/backup.js';

test('backs up and restores operational state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-backup-'));
  await mkdir(join(root, '.sentrycode'), { recursive: true });
  await writeFile(join(root, '.sentrycode/config.json'), '{"v":1}\n');
  const backup = await createBackup(root, ['.sentrycode/config.json'], '.sentrycode/backups');
  await writeFile(join(root, '.sentrycode/config.json'), '{"v":2}\n');
  await restoreBackup(root, backup, { 'config.json': '.sentrycode/config.json' });
  assert.match(await readFile(join(root, '.sentrycode/config.json'), 'utf8'), /"v":1/);
  assert.match(basename(backup), /^backup-/);
});
