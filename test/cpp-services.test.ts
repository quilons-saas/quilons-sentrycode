import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverServices } from '../src/monorepo/discover.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('classifies CMake Conan and vcpkg service roots as C/C++',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-cpp-services-'));
  for(const name of ['engine','native-lib','gateway'])await mkdir(join(root,name));
  await writeFile(join(root,'engine','CMakeLists.txt'),'cmake_minimum_required(VERSION 3.24)\n');
  await writeFile(join(root,'native-lib','conanfile.txt'),'[requires]\nfmt/11.0.2\n');
  await writeFile(join(root,'gateway','vcpkg.json'),JSON.stringify({name:'gateway',version:'1.0.0'}));
  const config=structuredClone(DEFAULT_CONFIG); config.monorepo.serviceRoots=['engine','native-lib','gateway'];
  const services=await discoverServices(root,config);
  assert.deepEqual(services.map(x=>x.kind),['cpp','cpp','cpp']);
});
