import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { loadConfig } from '../src/config/load.js';

test('CRA reporting is disabled by default and does not alter Compliance read API configuration', () => {
  assert.equal(DEFAULT_CONFIG.craReporting.enabled, false);
  assert.equal(DEFAULT_CONFIG.craReporting.endpoint, '');
  assert.equal(DEFAULT_CONFIG.craReporting.maxAttempts, 5);
  assert.equal(DEFAULT_CONFIG.craReporting.retryDelayMs, 30000);
  assert.deepEqual(DEFAULT_CONFIG.craReporting.severities, ['high', 'critical']);
  assert.deepEqual(DEFAULT_CONFIG.craReporting.findingTypes, []);
  assert.equal(DEFAULT_CONFIG.compliance.listenPort, 7786);
  assert.equal(DEFAULT_CONFIG.compliance.apiTokenEnv, 'SENTRYCODE_PLUGIN_API_TOKEN');
});

test('CRA reporting config loads additively and reuses Compliance tenant/project identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-cra-config-'));
  await mkdir(join(root, '.sentrycode'), { recursive: true });
  await writeFile(join(root, '.sentrycode', 'config.json'), JSON.stringify({
    schemaVersion: 1,
    compliance: { tenant: 'acme', project: 'payments', listenPort: 7786 },
    craReporting: { enabled: true, endpoint: 'https://cra.example/integration', tokenEnv: 'CRA_TOKEN', timeoutMs: 9000, maxAttempts: 7, retryDelayMs: 12000, severities: ['critical'], findingTypes: ['vulnerability', 'sast'] }
  }));
  const config = await loadConfig(root);
  assert.equal(config.compliance.tenant, 'acme');
  assert.equal(config.compliance.project, 'payments');
  assert.equal(config.compliance.listenPort, 7786);
  assert.equal(config.craReporting.enabled, true);
  assert.equal(config.craReporting.endpoint, 'https://cra.example/integration');
  assert.equal(config.craReporting.tokenEnv, 'CRA_TOKEN');
  assert.equal(config.craReporting.timeoutMs, 9000);
  assert.equal(config.craReporting.maxAttempts, 7);
  assert.equal(config.craReporting.retryDelayMs, 12000);
  assert.deepEqual(config.craReporting.severities, ['critical']);
  assert.deepEqual(config.craReporting.findingTypes, ['vulnerability', 'sast']);
});

test('CRA reporting rejects invalid severity configuration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-cra-config-bad-'));
  await mkdir(join(root, '.sentrycode'), { recursive: true });
  await writeFile(join(root, '.sentrycode', 'config.json'), JSON.stringify({ schemaVersion:1, craReporting:{ severities:['blocker'] } }));
  await assert.rejects(loadConfig(root), /craReporting.severities must contain valid severities/);
});
