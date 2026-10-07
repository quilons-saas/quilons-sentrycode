import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { RunnerClient } from '../src/execution/runner-client.js';
import { sha256, type RunnerJobRequestV1 } from '../src/execution/contracts.js';

async function fakeRunner(tamper = false): Promise<{ endpoint: string; close: () => Promise<void> }> {
  const server = createServer(async (req, res) => {
    assert.equal(req.headers.authorization, 'Bearer token-1');
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RunnerJobRequestV1;
    assert.equal(body.scope.tenant, 'tenant-a'); assert.equal(body.scope.project, 'project-a');
    const syft = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }));
    const grype = Buffer.from(JSON.stringify({ matches: [] }));
    const response = {
      schemaVersion: 1, runId: body.runId, scope: body.scope, profileId: body.profileId, profileDigest: 'a'.repeat(64), rulesIdentity: 'db:test', inputDigest: body.input.digest,
      outcome: 'completed', cleanupConfirmed: true,
      artifacts: [
        { name: 'syft.cdx.json', sha256: tamper ? '0'.repeat(64) : sha256(syft), bytes: syft.length, contentBase64: syft.toString('base64') },
        { name: 'grype.json', sha256: sha256(grype), bytes: grype.length, contentBase64: grype.toString('base64') }
      ], steps: [], events: []
    };
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(response));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('no address');
  return { endpoint: `http://127.0.0.1:${address.port}`, close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())) };
}

test('runner client binds authenticated request to scope/profile/input and verifies artifacts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-client-')); const fake = await fakeRunner();
  try {
    await writeFile(join(root, 'a.txt'), 'abc');
    const client = new RunnerClient({ endpoint: fake.endpoint, token: 'token-1', tenant: 'tenant-a', project: 'project-a', timeoutMs: 5000 });
    const result = await client.runRepositoryProfile({ runId: 'run-1', profileId: 'syft-grype', repositoryRoot: root, config: structuredClone(DEFAULT_CONFIG) });
    assert.equal(result.outcome, 'completed'); assert.equal(result.cleanupConfirmed, true);
  } finally { await fake.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner client fails closed on artifact integrity mismatch', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-client-tamper-')); const fake = await fakeRunner(true);
  try {
    await writeFile(join(root, 'a.txt'), 'abc');
    const client = new RunnerClient({ endpoint: fake.endpoint, token: 'token-1', tenant: 'tenant-a', project: 'project-a', timeoutMs: 5000 });
    await assert.rejects(() => client.runRepositoryProfile({ runId: 'run-2', profileId: 'syft-grype', repositoryRoot: root, config: structuredClone(DEFAULT_CONFIG) }), /artifact integrity failure/);
  } finally { await fake.close(); await rm(root, { recursive: true, force: true }); }
});
