import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDependencyFiles } from '../src/dependencies/discover.js';

const now='2026-08-30T00:00:00.000Z';

test('discovers Conan direct and locked dependencies with Conan purls',()=>{
  const snapshot=parseDependencyFiles({
    'conanfile.txt':'[requires]\nopenssl/3.3.1\nzlib/1.3.1\n[tool_requires]\ncmake/3.30.0\n',
    'conan.lock':JSON.stringify({graph_lock:{nodes:{'0':{ref:'openssl/3.3.1#rrev'},'1':{ref:'fmt/11.0.2@vendor/stable'}}}})
  },now);
  const openssl=snapshot.components.find(x=>x.ecosystem==='conan'&&x.name==='openssl');
  assert.equal(openssl?.version,'3.3.1');
  assert.equal(openssl?.direct,true);
  assert.equal(openssl?.purl,'pkg:conan/openssl@3.3.1');
  assert.equal(snapshot.components.find(x=>x.name==='fmt')?.direct,false);
  assert.equal(snapshot.components.find(x=>x.name==='cmake')?.dev,true);
});

test('discovers resolved vcpkg dependencies with vcpkg purls',()=>{
  const snapshot=parseDependencyFiles({
    'vcpkg.json':JSON.stringify({dependencies:[{name:'openssl','version>=':'3.3.1'},{name:'fmt','version':'11.0.2'},'zlib']}),
    'vcpkg-lock.json':JSON.stringify({dependencies:[{name:'openssl','version-string':'3.3.1'},{name:'zlib','version':'1.3.1'}]})
  },now);
  const fmt=snapshot.components.find(x=>x.ecosystem==='vcpkg'&&x.name==='fmt');
  assert.equal(fmt?.direct,true);
  assert.equal(fmt?.purl,'pkg:vcpkg/fmt@11.0.2');
  assert.equal(snapshot.components.find(x=>x.name==='zlib')?.version,'1.3.1');
});
