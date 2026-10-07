import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RunnerLease } from '../src/execution/runner-lease.js';

test('runner lease prevents duplicate installation owners and releases cleanly', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-lease-'));
  const first = new RunnerLease(root, 5000, 500);
  const second = new RunnerLease(root, 5000, 500);
  try {
    await first.acquire();
    await assert.rejects(() => second.acquire(), /Another SentryCode runner owns this installation/);
    await first.release();
    await second.acquire();
    await second.release();
  } finally { await first.release().catch(() => undefined); await second.release().catch(() => undefined); await rm(root, { recursive: true, force: true }); }
});

test('runner lease can recover an abandoned stale owner', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-lease-stale-'));
  const leaseDir = join(root, '.runner-lease');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(leaseDir);
  await writeFile(join(leaseDir, 'owner.json'), JSON.stringify({ owner: 'dead', heartbeatAt: Date.now() - 10000 }));
  const lease = new RunnerLease(root, 3000, 500);
  try { await lease.acquire(); await lease.release(); }
  finally { await lease.release().catch(() => undefined); await rm(root, { recursive: true, force: true }); }
});
