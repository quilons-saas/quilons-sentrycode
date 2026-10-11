import test from 'node:test';
import assert from 'node:assert/strict';

import { ownershipFallbackAllowed, prepareWorkerOutputDirectory } from '../src/execution/docker-executor.js';

test('output ownership fallback is restricted to permission-style chown failures', () => {
  assert.equal(ownershipFallbackAllowed(Object.assign(new Error('not permitted'), { code: 'EPERM' })), true);
  assert.equal(ownershipFallbackAllowed(Object.assign(new Error('denied'), { code: 'EACCES' })), true);
  assert.equal(ownershipFallbackAllowed(Object.assign(new Error('missing'), { code: 'ENOENT' })), false);
  assert.equal(ownershipFallbackAllowed(new Error('generic')), false);
});

test('output preparation keeps native chown path when ownership change is supported', async () => {
  const calls: string[] = [];
  const result = await prepareWorkerOutputDirectory(
    '/ignored/native',
    'linux',
    async (_path, uid, gid) => { calls.push(`chown:${uid}:${gid}`); },
    async (_path, mode) => { calls.push(`chmod:${mode.toString(8)}`); }
  );

  assert.equal(result, 'owned');
  assert.deepEqual(calls, ['chmod:770', 'chown:65532:65532']);
});

test('output preparation falls back to job-local writable mode only for EPERM', async () => {
  const calls: string[] = [];
  const denied = Object.assign(new Error('operation not permitted'), { code: 'EPERM' });

  const result = await prepareWorkerOutputDirectory(
    '/ignored/portable',
    'linux',
    async () => { throw denied; },
    async (_path, mode) => { calls.push(`chmod:${mode.toString(8)}`); }
  );

  assert.equal(result, 'portable-permissions');
  assert.deepEqual(calls, ['chmod:770', 'chmod:777']);
});

test('output preparation remains fail-closed for unexpected ownership errors', async () => {
  const unexpected = Object.assign(new Error('I/O failure'), { code: 'EIO' });

  await assert.rejects(
    () => prepareWorkerOutputDirectory(
      '/ignored/error',
      'linux',
      async () => { throw unexpected; },
      async () => undefined
    ),
    /I\/O failure/
  );
});