import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
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
