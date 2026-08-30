import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { parseDependencyFiles } from '../src/dependencies/discover.js';
import { cyclonedxSbom, spdxSbom } from '../src/sbom/generate.js';
import { SastScanner } from '../src/scanners/sast/scanner.js';
import { discoverServices } from '../src/monorepo/discover.js';
import type { DependencyComponent, RepositoryContext, SastLanguage } from '../src/core/types.js';

const now = '2026-08-30T00:00:00.000Z';

const dependencyFiles: Record<string,string> = {
  'package-lock.json': JSON.stringify({ name:'js-app', lockfileVersion:3, packages:{ '':{name:'js-app',version:'1.0.0'}, 'node_modules/lodash':{version:'4.17.21',license:'MIT'} } }),
  'requirements.txt': 'requests==2.32.3\n',
  'pom.xml': '<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>',
  'Demo.csproj': '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>',
  'conanfile.txt': '[requires]\nfmt/10.2.1\n',
  'vcpkg-lock.json': JSON.stringify({ dependencies: [{ name:'zlib', version:'1.3.1' }] }),
  'vcpkg.json': JSON.stringify({ name:'native-app', version:'1.0.0', dependencies:[{name:'zlib', 'version>=':'1.3.1'}] }),
  'Cargo.toml': '[package]\nname="rust-app"\nversion="1.0.0"\n[dependencies]\nserde = "1"\n',
  'Cargo.lock': '[[package]]\nname = "serde"\nversion = "1.0.219"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
  'go.mod': 'module example.com/go-app\n\ngo 1.24\nrequire github.com/google/uuid v1.6.0\n'
};

test('market readiness default native language matrix is complete', () => {
  const expected: SastLanguage[] = ['javascript','typescript','python','java','csharp','c','cpp','rust','go'];
  assert.deepEqual([...DEFAULT_CONFIG.sast.languages].sort(), [...expected].sort());
});

test('market readiness dependency matrix covers every supported ecosystem with purls', () => {
  const snapshot = parseDependencyFiles(dependencyFiles, now);
  const expected = ['npm','pypi','maven','nuget','conan','vcpkg','cargo','go'];
  const actual = new Set(snapshot.components.map((component) => component.ecosystem));
  for (const ecosystem of expected) assert.equal(actual.has(ecosystem as DependencyComponent['ecosystem']), true, `missing ${ecosystem}`);
  for (const component of snapshot.components) assert.match(component.purl, /^pkg:/);
});

test('market readiness SBOM formats serialize the full dependency matrix', () => {
  const components = parseDependencyFiles(dependencyFiles, now).components;
  const repository: RepositoryContext = { root:'/acceptance', repository:'market-readiness', commitSha:'abc123', branch:'main', isDirty:false };
  const cdx = cyclonedxSbom(repository, components, now) as { bomFormat:string; specVersion:string; components: unknown[] };
  const spdx = spdxSbom(repository, components, now) as { spdxVersion:string; packages: unknown[] };
  assert.equal(cdx.bomFormat, 'CycloneDX');
  assert.equal(cdx.specVersion, '1.5');
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
  assert.equal(cdx.components.length, components.length);
  assert.equal(spdx.packages.length, components.length + 1);
});

test('market readiness native SAST executes across every supported source language', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-market-sast-'));
  try {
    const files: Record<string,string> = {
      'app.js':'eval(input);',
      'app.ts':'eval(input);',
      'app.py':'eval(user_input)',
      'App.java':'class App { void x(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }',
      'App.cs':'class App { void X(string x) { System.Diagnostics.Process.Start(x); } }',
      'app.c':'int main(){ char b[8]; gets(b); }',
      'app.cpp':'int main(){ char b[8]; strcpy(b, input); }',
      'lib.rs':'fn x(v: Vec<u8>) { unsafe { String::from_utf8_unchecked(v); } }',
      'main.go':'package main\nimport "crypto/tls"\nvar c=&tls.Config{InsecureSkipVerify:true}\n'
    };
    for (const [name,content] of Object.entries(files)) await writeFile(join(root,name), content);
    const scanner = new SastScanner();
    const result = await scanner.scan({
      repository:{root,repository:'market-readiness',commitSha:'abc',branch:'main',isDirty:false},
      config: DEFAULT_CONFIG,
      now:()=>new Date(now)
    });
    const paths = new Set(result.findings.map((finding)=>finding.location?.path));
    for (const name of Object.keys(files)) assert.equal(paths.has(name), true, `no native SAST finding for ${name}`);
  } finally {
    await rm(root,{recursive:true,force:true});
  }
});

test('market readiness monorepo classification covers every supported service family', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-market-services-'));
  try {
    const markers: Array<[string,string,string]> = [
      ['node','package.json','{}'],
      ['python','requirements.txt','requests==2.32.3'],
      ['java','pom.xml','<project/>'],
      ['dotnet','App.csproj','<Project/>'],
      ['cpp','CMakeLists.txt','cmake_minimum_required(VERSION 3.20)'],
      ['rust','Cargo.toml','[package]\nname="x"\nversion="1.0.0"'],
      ['go','go.mod','module example.com/x']
    ];
    for (const [dir,file,content] of markers) {
      await mkdir(join(root,dir),{recursive:true});
      await writeFile(join(root,dir,file),content);
    }
    const config = structuredClone(DEFAULT_CONFIG);
    config.monorepo.serviceRoots = markers.map(([dir])=>dir);
    const services = await discoverServices(root, config);
    const byRoot = new Map(services.map((service)=>[service.root,service.kind]));
    for (const [dir] of markers) assert.equal(byRoot.get(dir), dir);
  } finally {
    await rm(root,{recursive:true,force:true});
  }
});
