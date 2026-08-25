import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { syncOsvDatabase } from '../src/vulnerabilities/osv.js';

test('OSV sync builds local advisory database for discovered package versions',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-osv-')); await writeFile(join(root,'requirements.txt'),'jinja2==2.4.1\n'); const config=structuredClone(DEFAULT_CONFIG); config.vulnerabilities.databaseFile='.sentrycode/vulnerability-db.json';
  const previous=globalThis.fetch;
  globalThis.fetch=async(input)=>{ const url=String(input); if(url.endsWith('/v1/querybatch')) return new Response(JSON.stringify({results:[{vulns:[{id:'GHSA-test'}]}]}),{status:200}); return new Response(JSON.stringify({id:'GHSA-test',summary:'Example vuln',database_specific:{severity:'HIGH'},affected:[{ranges:[{events:[{introduced:'0'},{fixed:'2.5.0'}]}]}]}),{status:200}); };
  try { const result=await syncOsvDatabase(root,config); assert.equal(result.advisoryCount,1); const db=JSON.parse(await readFile(join(root,'.sentrycode/vulnerability-db.json'),'utf8')) as {advisories:Array<{id:string;affected:string;fixedVersion?:string}>}; assert.equal(db.advisories[0]?.id,'GHSA-test'); assert.equal(db.advisories[0]?.affected,'=2.4.1'); assert.equal(db.advisories[0]?.fixedVersion,'2.5.0'); }
  finally { globalThis.fetch=previous; }
});
