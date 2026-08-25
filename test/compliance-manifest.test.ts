import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadPluginManifest } from '../src/compliance/manifest.js';

 test('plugin manifest advertises standalone governed capabilities', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-manifest-'));
  await writeFile(join(root, 'package.json'), JSON.stringify({ version: '0.1.0' }));
  const manifest = await loadPluginManifest(root);
  assert.equal(manifest.pluginId, 'quilons.sentrycode');
  assert.equal(manifest.standalone, true);
  assert.equal(manifest.apiVersion, '1.0.0');
  assert.ok(manifest.capabilities.some((item) => item.id === 'sentrycode.evidence'));
  assert.ok(manifest.evidenceTypes.includes('policy.eval'));
});
