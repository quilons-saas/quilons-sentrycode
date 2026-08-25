import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { affectedServices, discoverServices } from '../src/monorepo/discover.js';

test('discovers npm workspace services and affected service', async () => {
  const root=await mkdtemp(resolve(tmpdir(),'sc-mono-'));
  await mkdir(resolve(root,'packages/api'),{recursive:true});
  await mkdir(resolve(root,'packages/web'),{recursive:true});
  await writeFile(resolve(root,'package.json'),JSON.stringify({workspaces:['packages/*']}));
  await writeFile(resolve(root,'packages/api/package.json'),'{}');
  await writeFile(resolve(root,'packages/web/package.json'),'{}');
  const services=await discoverServices(root,DEFAULT_CONFIG);
  assert.deepEqual(services.map(x=>x.root),['packages/api','packages/web']);
  assert.deepEqual(affectedServices(['packages/api/src/index.ts'],services).map(x=>x.root),['packages/api']);
});
