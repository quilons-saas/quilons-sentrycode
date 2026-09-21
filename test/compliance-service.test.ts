import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SentryCodeComplianceService } from '../src/compliance/service.js';

 test('compliance health and readiness expose installer-safe probes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-ready-'));
  await writeFile(join(root, 'package.json'), '{}');
  const service = new SentryCodeComplianceService(root, '.sentrycode/compliance');
  assert.equal(service.health().status, 'ok');
  const ready = await service.readiness();
  assert.equal(ready.ready, true);
  assert.ok(ready.checks.every((item) => item.ok));
});


test('compliance readiness materializes and validates the configured evidence store', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-ready-store-'));
  await writeFile(join(root, 'package.json'), '{}');
  const service = new SentryCodeComplianceService(root, '.state/compliance');
  const ready = await service.readiness();
  assert.equal(ready.ready, true);
  assert.equal(ready.checks.find((item) => item.id === 'store')?.ok, true);
  await access(join(root, '.state', 'compliance'));
});
