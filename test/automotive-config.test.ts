import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config/load.js';

test('loads automotive adapter configuration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-auto-config-'));
  await mkdir(join(root, '.sentrycode'));
  await writeFile(join(root, '.sentrycode', 'config.json'), JSON.stringify({ schemaVersion: 1, automotive: { enabled: true, acceptedStandards: ['misra-c', 'autosar-cpp'], evidenceTargets: ['iso-sae-21434', 'unece-r155'], requireInputs: true } }));
  const config = await loadConfig(root);
  assert.equal(config.automotive.enabled, true);
  assert.deepEqual(config.automotive.acceptedStandards, ['misra-c', 'autosar-cpp']);
  assert.deepEqual(config.automotive.evidenceTargets, ['iso-sae-21434', 'unece-r155']);
  assert.equal(config.automotive.requireInputs, true);
});
