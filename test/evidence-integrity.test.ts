import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeIntegrityManifest, verifyIntegrityManifest } from '../src/enterprise/evidence-integrity.js';

test('evidence integrity manifest detects tampering', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-evidence-'));
  await writeFile(join(root, 'report.json'), '{"decision":"PASS"}\n');
  await writeIntegrityManifest(root);
  assert.equal((await verifyIntegrityManifest(root)).ok, true);
  await writeFile(join(root, 'report.json'), '{"decision":"FAIL"}\n');
  const result = await verifyIntegrityManifest(root);
  assert.equal(result.ok, false);
  assert.deepEqual(result.mismatches, ['report.json']);
});
