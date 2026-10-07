import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { canonicalInputDigest, snapshotRepository } from '../src/execution/snapshot.js';

function config() { return structuredClone(DEFAULT_CONFIG); }

test('repository snapshot is deterministic and excludes configured paths', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-snapshot-'));
  try {
    await writeFile(join(root, 'a.ts'), 'const a = 1;');
    await mkdir(join(root, 'src')); await writeFile(join(root, 'src', 'b.ts'), 'const b = 2;');
    await mkdir(join(root, 'node_modules')); await writeFile(join(root, 'node_modules', 'ignored.js'), 'ignored');
    const first = await snapshotRepository(root, config());
    const second = await snapshotRepository(root, config());
    assert.deepEqual(first.files.map((file) => file.path), ['a.ts', 'src/b.ts']);
    assert.equal(first.digest, second.digest);
    assert.equal(first.digest, canonicalInputDigest(first.files));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('repository snapshot enforces aggregate file and byte bounds', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-snapshot-limit-'));
  try {
    await writeFile(join(root, 'a.txt'), '12345');
    await writeFile(join(root, 'b.txt'), '67890');
    await assert.rejects(() => snapshotRepository(root, config(), { maxFiles: 1, maxTotalBytes: 100, maxFileBytes: 100 }), /file limit/);
    await assert.rejects(() => snapshotRepository(root, config(), { maxFiles: 10, maxTotalBytes: 8, maxFileBytes: 100 }), /byte limit/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
