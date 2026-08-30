import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverServices } from '../src/monorepo/discover.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('monorepo service discovery classifies Java and .NET service roots',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-java-dotnet-services-'));
  await mkdir(join(root,'services','orders'),{recursive:true}); await writeFile(join(root,'services','orders','pom.xml'),'<project/>');
  await mkdir(join(root,'services','billing'),{recursive:true}); await writeFile(join(root,'services','billing','Billing.csproj'),'<Project/>');
  const config=structuredClone(DEFAULT_CONFIG); config.monorepo.serviceRoots=['services/orders','services/billing'];
  const services=await discoverServices(root,config);
  assert.equal(services.find(s=>s.name==='orders')?.kind,'java');
  assert.equal(services.find(s=>s.name==='billing')?.kind,'dotnet');
});
