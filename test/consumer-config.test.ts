import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { loadConfig } from '../src/config/load.js';

test('consumer registry configuration is empty by default', () => {
  assert.deepEqual(DEFAULT_CONFIG.consumers, []);
});

test('multiple consumer configurations load without client-domain fields in the core schema', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-consumer-config-'));
  await mkdir(join(root, '.sentrycode'), { recursive: true });
  await writeFile(join(root, '.sentrycode', 'config.json'), JSON.stringify({
    schemaVersion: 1,
    consumers: [
      {
        consumerId: 'cra', adapter: 'cra', enabled: true, endpoint: 'https://cra.example/invoke', tokenEnv: 'CRA_TOKEN',
        scanProfile: { requiredScanners: ['dependencies', 'sast'], evidenceTypes: ['finding.evidence'], severities: ['high', 'critical'], findingTypes: ['vulnerability'] },
        context: { assessmentId: 'assessment-1' }
      },
      {
        consumerId: 'cyber', adapter: 'cyber', enabled: true, endpoint: 'https://cyber.example/invoke', tokenEnv: 'CYBER_TOKEN',
        scanProfile: { requiredScanners: ['dependencies', 'secrets', 'provenance'] },
        context: { binding: 'build-1' }
      }
    ]
  }));
  const config = await loadConfig(root);
  assert.equal(config.consumers.length, 2);
  assert.equal(config.consumers[0]!.consumerId, 'cra');
  assert.deepEqual(config.consumers[0]!.scanProfile.severities, ['high', 'critical']);
  assert.deepEqual(config.consumers[1]!.scanProfile.requiredScanners, ['dependencies', 'secrets', 'provenance']);
  assert.equal(config.consumers[1]!.timeoutMs, 15000);
  assert.equal(config.consumers[1]!.maxAttempts, 5);
});

test('duplicate consumer IDs fail closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-consumer-duplicate-'));
  await mkdir(join(root, '.sentrycode'), { recursive: true });
  await writeFile(join(root, '.sentrycode', 'config.json'), JSON.stringify({ schemaVersion: 1, consumers: [
    { consumerId: 'cra', adapter: 'cra' }, { consumerId: 'cra', adapter: 'cra' }
  ] }));
  await assert.rejects(loadConfig(root), /Duplicate consumerId: cra/);
});

test('invalid consumer severity fails closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-consumer-severity-'));
  await mkdir(join(root, '.sentrycode'), { recursive: true });
  await writeFile(join(root, '.sentrycode', 'config.json'), JSON.stringify({ schemaVersion: 1, consumers: [
    { consumerId: 'cra', adapter: 'cra', scanProfile: { severities: ['blocker'] } }
  ] }));
  await assert.rejects(loadConfig(root), /scanProfile.severities must contain valid severities/);
});
