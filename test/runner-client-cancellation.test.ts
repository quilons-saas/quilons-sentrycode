import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { RunnerClient } from '../src/execution/runner-client.js';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'sc-client-2a-'));
  await writeFile(join(root, 'a.txt'), 'a');
  return root;
}

test('runner client preserves typed execution failure returned as HTTP 422', async () => {
  const root = await fixture();
  const server = createServer(async (req, res) => {
    if (req.method !== 'POST') { res.writeHead(404).end(); return; }
    const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const request = JSON.parse(Buffer.concat(chunks).toString('utf8')) as any;
    const body = JSON.stringify({
      schemaVersion: 1, runId: request.runId, scope: request.scope, profileId: request.profileId, profileVersion: 'test', profileDigest: 'a'.repeat(64), rulesIdentity: 'rules:test', inputDigest: request.input.digest,
      outcome: 'failed', errorCode: 'SCANNER_EXECUTION_FAILED', artifacts: [], steps: [], events: [], cleanupConfirmed: true
    });
    res.writeHead(422, { 'content-type': 'application/json' }).end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('server address unavailable');
  try {
    const config = structuredClone(DEFAULT_CONFIG);
    const result = await new RunnerClient({ endpoint: `http://127.0.0.1:${address.port}`, token: 'token', tenant: 't', project: 'p', timeoutMs: 5000 })
      .runRepositoryProfile({ runId: 'typed-failure', profileId: 'syft-grype', repositoryRoot: root, config });
    assert.equal(result.outcome, 'failed');
    assert.equal(result.errorCode, 'SCANNER_EXECUTION_FAILED');
  } finally { server.close(); await rm(root, { recursive: true, force: true }); }
});

test('runner client issues authenticated cancellation when caller aborts an active job', async () => {
  const root = await fixture();
  let deleteSeen = false;
  let deleteAuth = '';
  const server = createServer(async (req, res) => {
    if (req.method === 'DELETE') {
      deleteSeen = true; deleteAuth = req.headers.authorization ?? '';
      res.writeHead(202, { 'content-type': 'application/json' }).end('{"cancelled":true}');
      return;
    }
    if (req.method === 'POST') {
      req.resume();
      await new Promise((resolve) => setTimeout(resolve, 1000));
      if (!res.destroyed) res.writeHead(500).end('late');
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('server address unavailable');
  try {
    const config = structuredClone(DEFAULT_CONFIG);
    const controller = new AbortController();
    const run = new RunnerClient({ endpoint: `http://127.0.0.1:${address.port}`, token: 'secret', tenant: 't', project: 'p', timeoutMs: 5000 })
      .runRepositoryProfile({ runId: 'cancel-me', profileId: 'syft-grype', repositoryRoot: root, config, signal: controller.signal });
    setTimeout(() => controller.abort(new Error('test cancellation')), 50);
    await assert.rejects(run, /cancelled/);
    assert.equal(deleteSeen, true);
    assert.equal(deleteAuth, 'Bearer secret');
  } finally { server.close(); await rm(root, { recursive: true, force: true }); }
});
