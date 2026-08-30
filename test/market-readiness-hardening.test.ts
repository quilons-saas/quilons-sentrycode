import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseDependencyFiles } from '../src/dependencies/discover.js';
import { dependencySnapshotAtRef, diffDependencies } from '../src/dependencies/diff.js';
import { cyclonedxSbom, spdxSbom } from '../src/sbom/generate.js';
import { DependencyScanner } from '../src/scanners/dependencies/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

const execFileAsync=promisify(execFile);
const now='2026-08-30T00:00:00.000Z';

test('cross-ecosystem Git ref dependency diff reads nested supported manifests',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-diff-all-'));
  try{
    await execFileAsync('git',['init'],{cwd:root}); await execFileAsync('git',['config','user.email','test@example.com'],{cwd:root}); await execFileAsync('git',['config','user.name','Test'],{cwd:root});
    const initial:Record<string,string>={
      'js/package-lock.json':JSON.stringify({lockfileVersion:3,packages:{'node_modules/a':{version:'1.0.0'}}}),
      'py/requirements.txt':'requests==2.31.0\n','java/pom.xml':'<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0.0</version></dependency></dependencies></project>',
      'dotnet/App.csproj':'<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.2" /></ItemGroup></Project>',
      'cpp/conanfile.txt':'[requires]\nfmt/10.1.0\n','rust/Cargo.toml':'[dependencies]\nserde="1"\n','rust/Cargo.lock':'[[package]]\nname = "serde"\nversion = "1.0.200"\n',
      'go/go.mod':'module x\nrequire github.com/google/uuid v1.5.0\n'
    };
    for(const [name,content] of Object.entries(initial)){await mkdir(join(root,name.split('/').slice(0,-1).join('/')),{recursive:true});await writeFile(join(root,name),content);}
    await execFileAsync('git',['add','.'],{cwd:root});await execFileAsync('git',['commit','-m','before'],{cwd:root});const before=(await execFileAsync('git',['rev-parse','HEAD'],{cwd:root})).stdout.trim();
    const changed={...initial,'py/requirements.txt':'requests==2.32.3\n','java/pom.xml':initial['java/pom.xml']!.replace('1.0.0','2.0.0'),'dotnet/App.csproj':initial['dotnet/App.csproj']!.replace('13.0.2','13.0.3'),'cpp/conanfile.txt':'[requires]\nfmt/10.2.1\n','rust/Cargo.lock':initial['rust/Cargo.lock']!.replace('1.0.200','1.0.219'),'go/go.mod':'module x\nrequire github.com/google/uuid v1.6.0\n'};
    for(const [name,content] of Object.entries(changed))await writeFile(join(root,name),content);await execFileAsync('git',['add','.'],{cwd:root});await execFileAsync('git',['commit','-m','after'],{cwd:root});
    const beforeSnap=await dependencySnapshotAtRef(root,before,now);const afterSnap=await dependencySnapshotAtRef(root,'HEAD',now);const changes=diffDependencies(beforeSnap,afterSnap);const ecosystems=new Set(changes.map(c=>c.ecosystem));
    for(const ecosystem of ['pypi','maven','nuget','conan','cargo','go'])assert.equal(ecosystems.has(ecosystem as any),true,`missing diff for ${ecosystem}`);
  }finally{await rm(root,{recursive:true,force:true});}
});

test('Go replace and exclude govern the effective dependency set',()=>{
  const snap=parseDependencyFiles({'go.mod':'module x\nrequire (\n example.com/a v1.0.0\n example.com/b v2.0.0\n)\nexclude example.com/b v2.0.0\nreplace example.com/a v1.0.0 => example.com/fork/a v1.1.0\n'},now);
  assert.equal(snap.components.some(c=>c.name==='example.com/b'),false);const a=snap.components.find(c=>c.ecosystem==='go');assert.equal(a?.name,'example.com/fork/a');assert.equal(a?.version,'v1.1.0');assert.equal(a?.replacedFrom,'example.com/a@v1.0.0');
});

test('Maven dependency management resolves direct dependency versions and Python lockfiles are recognized',()=>{
  const snap=parseDependencyFiles({
    'pom.xml':'<project><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>2.4.0</version></dependency></dependencies></dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId></dependency></dependencies></project>',
    'poetry.lock':'[[package]]\nname = "httpx"\nversion = "0.28.1"\ncategory = "main"\n','uv.lock':'[[package]]\nname = "anyio"\nversion = "4.8.0"\n'
  },now);
  assert.equal(snap.components.some(c=>c.ecosystem==='maven'&&c.version==='2.4.0'),true);assert.equal(snap.components.some(c=>c.ecosystem==='pypi'&&c.name==='httpx'),true);assert.equal(snap.components.some(c=>c.ecosystem==='pypi'&&c.name==='anyio'),true);
});

test('SBOM emits package hashes, application dependency relationships, and correct tool version',()=>{
  const digest=Buffer.alloc(32,7);const snap=parseDependencyFiles({'package-lock.json':JSON.stringify({lockfileVersion:3,packages:{'node_modules/a':{version:'1.0.0',integrity:`sha256-${digest.toString('base64')}`,dependencies:{b:'1.0.0'}},'node_modules/b':{version:'1.0.0'}}})},now);const repo={root:'/',repository:'x',commitSha:'abc',branch:'main',isDirty:false};
  const cdx=cyclonedxSbom(repo,snap.components,now) as any;const spdx=spdxSbom(repo,snap.components,now) as any;
  assert.equal(cdx.components.some((c:any)=>c.hashes?.[0]?.alg==='SHA-256'),true);assert.equal(cdx.dependencies.some((d:any)=>d.dependsOn?.length),true);assert.equal(spdx.creationInfo.creators[0],'Tool: QUILONS SentryCode-0.1.0');assert.equal(spdx.packages.some((p:any)=>p.checksums?.length),true);assert.equal(spdx.relationships.some((r:any)=>r.relationshipType==='DEPENDS_ON'),true);
});

test('dependency governance enforces denied registries and governed maintenance criteria',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-maint-'));try{await writeFile(join(root,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'node_modules/a':{version:'1.0.0',resolved:'https://evil.example/a.tgz'}}}));await mkdir(join(root,'.sentrycode'),{recursive:true});await writeFile(join(root,'.sentrycode/dependency-health.json'),JSON.stringify({packages:{'npm:a':{lastReleaseAt:'2020-01-01T00:00:00.000Z',deprecated:true}}}));const config=structuredClone(DEFAULT_CONFIG);config.dependencies.deniedRegistries=['evil.example'];config.dependencies.maintenance={enabled:true,metadataFile:'.sentrycode/dependency-health.json',maxReleaseAgeDays:365,denyDeprecated:true,requireMetadata:true};config.vulnerabilities.enabled=false;config.licenses.enabled=false;const result=await new DependencyScanner().scan({repository:{root,repository:'x',commitSha:'abc',branch:'main',isDirty:false},config,now:()=>new Date(now)});const rules=new Set(result.findings.map(f=>f.ruleId));assert.equal(rules.has('dependency.registry-denied'),true);assert.equal(rules.has('dependency.deprecated'),true);assert.equal(rules.has('dependency.stale'),true);}finally{await rm(root,{recursive:true,force:true});}
});
