import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SentryCodeComplianceService } from '../src/compliance/service.js';
import { startComplianceServer } from '../src/compliance/server.js';

test('capability API serves manifest and requires token on protected server', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-api-'));
  await writeFile(join(root, 'package.json'), JSON.stringify({ version:'0.1.0' }));
  const service = new SentryCodeComplianceService(root, '.sentrycode/compliance');
  const running = await startComplianceServer(service, { host:'127.0.0.1', port:0, token:'test-token' });
  try {
    const base = `http://127.0.0.1:${running.port}`;
    const unauthorized = await fetch(`${base}/v1/manifest`);
    assert.equal(unauthorized.status, 401);
    const response = await fetch(`${base}/v1/manifest`, { headers:{ authorization:'Bearer test-token' } });
    assert.equal(response.status, 200);
    const manifest = await response.json() as { pluginId:string };
    assert.equal(manifest.pluginId, 'quilons.sentrycode');
  } finally { await new Promise<void>((resolve, reject) => running.server.close((error?: Error) => error ? reject(error) : resolve())); }
});

test('non-loopback API exposure requires a bearer token', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-api-guard-'));
  const service = new SentryCodeComplianceService(root, '.sentrycode/compliance');
  await assert.rejects(startComplianceServer(service, { host:'0.0.0.0', port:0 }), /bearer token is required/);
});
