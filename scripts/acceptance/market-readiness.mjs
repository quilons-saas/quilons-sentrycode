import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../../dist/config/defaults.js';
import { parseDependencyFiles } from '../../dist/dependencies/discover.js';
import { cyclonedxSbom, spdxSbom } from '../../dist/sbom/generate.js';
import { SastScanner } from '../../dist/scanners/sast/scanner.js';

function pass(message){ process.stdout.write(`PASS ${message}\n`); }
function fail(message){ throw new Error(message); }

const now='2026-08-30T00:00:00.000Z';
const files={
  'package-lock.json': JSON.stringify({name:'js',lockfileVersion:3,packages:{'':{name:'js',version:'1.0.0'},'node_modules/lodash':{version:'4.17.21',license:'MIT'}}}),
  'requirements.txt':'requests==2.32.3\n',
  'pom.xml':'<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>',
  'App.csproj':'<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>',
  'conanfile.txt':'[requires]\nfmt/10.2.1\n',
  'vcpkg-lock.json':JSON.stringify({dependencies:[{name:'zlib',version:'1.3.1'}]}),
  'vcpkg.json':JSON.stringify({name:'native',version:'1.0.0',dependencies:[{name:'zlib','version>=':'1.3.1'}]}),
  'Cargo.toml':'[package]\nname="rust"\nversion="1.0.0"\n[dependencies]\nserde="1"\n',
  'Cargo.lock':'[[package]]\nname = "serde"\nversion = "1.0.219"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
  'go.mod':'module example.com/go\n\ngo 1.24\nrequire github.com/google/uuid v1.6.0\n'
};

const expectedLanguages=['javascript','typescript','python','java','csharp','c','cpp','rust','go'];
for(const language of expectedLanguages) if(!DEFAULT_CONFIG.sast.languages.includes(language)) fail(`native SAST language missing: ${language}`);
pass('native SAST language matrix covers JavaScript/TypeScript, Python, Java, C#, C/C++, Rust and Go');

const snapshot=parseDependencyFiles(files,now);
const expectedEcosystems=['npm','pypi','maven','nuget','conan','vcpkg','cargo','go'];
for(const ecosystem of expectedEcosystems) if(!snapshot.components.some((component)=>component.ecosystem===ecosystem)) fail(`dependency ecosystem missing: ${ecosystem}`);
if(snapshot.components.some((component)=>!component.purl.startsWith('pkg:'))) fail('dependency without purl');
pass('dependency discovery and purls cover npm, PyPI, Maven, NuGet, Conan, vcpkg, Cargo and Go modules');

const repository={root:'/acceptance',repository:'market-readiness',commitSha:'acceptance',branch:'main',isDirty:false};
const cdx=cyclonedxSbom(repository,snapshot.components,now);
const spdx=spdxSbom(repository,snapshot.components,now);
if(cdx.bomFormat!=='CycloneDX'||cdx.specVersion!=='1.5') fail('CycloneDX acceptance failed');
if(spdx.spdxVersion!=='SPDX-2.3') fail('SPDX acceptance failed');
if(cdx.components.length!==snapshot.components.length||spdx.packages.length!==snapshot.components.length+1) fail('SBOM component coverage mismatch');
if(!Array.isArray(cdx.dependencies)||!cdx.dependencies.length) fail('CycloneDX dependency graph missing');
if(!Array.isArray(spdx.relationships)||!spdx.relationships.some((r)=>r.relationshipType==='DEPENDS_ON')) fail('SPDX dependency relationships missing');
if(spdx.creationInfo?.creators?.[0]!=='Tool: QUILONS SentryCode-0.1.0') fail('SPDX tool version mismatch');
pass('CycloneDX 1.5 and SPDX 2.3 cover the complete dependency matrix with relationships');

const temp=await mkdtemp(join(tmpdir(),'sentrycode-market-readiness-'));
try{
  const sourceFiles={
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
  for(const [name,content] of Object.entries(sourceFiles)) await writeFile(join(temp,name),content);
  const scanner=new SastScanner();
  const result=await scanner.scan({repository:{root:temp,repository:'market-readiness',commitSha:'abc',branch:'main',isDirty:false},config:DEFAULT_CONFIG,now:()=>new Date(now)});
  const paths=new Set(result.findings.map((finding)=>finding.location?.path));
  for(const name of Object.keys(sourceFiles)) if(!paths.has(name)) fail(`native SAST acceptance missing finding for ${name}`);
  pass('native SAST executes across the complete supported language matrix');
} finally {
  await rm(temp,{recursive:true,force:true});
}

pass('cross-language market-readiness acceptance complete');
