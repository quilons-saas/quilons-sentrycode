import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverServices } from '../src/monorepo/discover.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('classifies Cargo and Go module service roots',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-rust-go-services-'));
  await mkdir(join(root,'rust-service')); await mkdir(join(root,'go-service'));
  await writeFile(join(root,'rust-service','Cargo.toml'),'[package]\nname="svc"\nversion="1.0.0"\n');
  await writeFile(join(root,'go-service','go.mod'),'module example.com/svc\n\ngo 1.24\n');
  const config=structuredClone(DEFAULT_CONFIG); config.monorepo.serviceRoots=['rust-service','go-service'];
  const services=await discoverServices(root,config);
  assert.deepEqual(services.map(x=>x.kind),['go','rust']);
});
