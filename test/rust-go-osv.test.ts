import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { syncOsvDatabase } from '../src/vulnerabilities/osv.js';

test('OSV synchronization maps Cargo and Go ecosystems correctly',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-rust-go-osv-'));
  await writeFile(join(root,'Cargo.toml'),'[package]\nname="demo"\nversion="1.0.0"\n[dependencies]\nserde="1"\n');
  await writeFile(join(root,'Cargo.lock'),'[[package]]\nname="serde"\nversion="1.0.219"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n');
  await writeFile(join(root,'go.mod'),'module example.com/demo\n\nrequire github.com/google/uuid v1.6.0\n');
  const config=structuredClone(DEFAULT_CONFIG); config.vulnerabilities.databaseFile='.sentrycode/vulnerability-db.json';
  const previous=globalThis.fetch; let queryBody:any;
  globalThis.fetch=async(input,init)=>{const url=String(input); if(url.endsWith('/v1/querybatch')){queryBody=JSON.parse(String(init?.body)); return new Response(JSON.stringify({results:[{},{}]}),{status:200});} return new Response(JSON.stringify({}),{status:200});};
  try{
    const result=await syncOsvDatabase(root,config); assert.equal(result.componentCount,2);
    assert.deepEqual(queryBody.queries.map((q:any)=>q.package.ecosystem).sort(),['Go','crates.io']);
  } finally { globalThis.fetch=previous; }
});
