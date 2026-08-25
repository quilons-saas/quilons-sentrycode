import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverDependencies } from '../src/dependencies/discover.js';
import { enrichDependencyMetadata } from '../src/dependencies/metadata.js';

test('service-scoped dependency discovery and local license enrichment',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-service-deps-')); const service=join(root,'apps','api'); await mkdir(join(service,'node_modules','left-pad'),{recursive:true});
  await writeFile(join(service,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{name:'api',version:'1.0.0'},'node_modules/left-pad':{version:'1.3.0',resolved:'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz'}}}));
  await writeFile(join(service,'node_modules','left-pad','package.json'),JSON.stringify({name:'left-pad',version:'1.3.0',license:'MIT'}));
  const snapshot=await discoverDependencies(root,'2026-08-25T00:00:00.000Z','apps/api'); const enriched=await enrichDependencyMetadata(root,snapshot.components,{serviceRoot:'apps/api'});
  assert.equal(enriched.length,1); assert.equal(enriched[0]?.name,'left-pad'); assert.equal(enriched[0]?.license,'MIT');
});
