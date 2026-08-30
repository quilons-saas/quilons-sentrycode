import { readFile, readdir } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import type { DependencyComponent, DependencySnapshot } from '../core/types.js';

interface PackageLock {
  packages?: Record<string, { name?: string; version?: string; dev?: boolean; resolved?: string; license?: string; integrity?: string; dependencies?: Record<string,string>; devDependencies?: Record<string,string>; optionalDependencies?: Record<string,string> }>;
  dependencies?: Record<string, { version?: string; dev?: boolean; resolved?: string; integrity?: string; requires?: Record<string,string> }>;
}

function sriHashes(integrity: string | undefined): DependencyComponent['hashes'] {
  if (!integrity) return undefined;
  const hashes: NonNullable<DependencyComponent['hashes']> = [];
  for (const token of integrity.trim().split(/\s+/)) {
    const match = token.match(/^(sha256|sha512)-(.+)$/i);
    if (!match) continue;
    try { hashes.push({ algorithm: match[1]!.toLowerCase() === 'sha256' ? 'SHA-256' : 'SHA-512', value: Buffer.from(match[2]!, 'base64').toString('hex') }); } catch {}
  }
  return hashes.length ? hashes : undefined;
}

function npmPurl(name: string, version: string): string {
  return `pkg:npm/${encodeURIComponent(name).replace('%40', '@')}@${encodeURIComponent(version)}`;
}
function pypiPurl(name: string, version: string): string {
  return `pkg:pypi/${encodeURIComponent(name.toLowerCase())}@${encodeURIComponent(version)}`;
}
function mavenPurl(group: string, artifact: string, version: string): string {
  return `pkg:maven/${encodeURIComponent(group)}/${encodeURIComponent(artifact)}@${encodeURIComponent(version)}`;
}
function nugetPurl(name: string, version: string): string {
  return `pkg:nuget/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}
function cargoPurl(name: string, version: string): string {
  return `pkg:cargo/${encodeURIComponent(name.toLowerCase())}@${encodeURIComponent(version)}`;
}
function goPurl(name: string, version: string): string {
  return `pkg:golang/${name.split('/').map((part)=>encodeURIComponent(part)).join('/')}@${encodeURIComponent(version)}`;
}
async function exists(path: string): Promise<boolean> {
  try { await readFile(path); return true; } catch { return false; }
}
async function maybeRead(path: string): Promise<string | undefined> {
  try { return await readFile(path, 'utf8'); } catch { return undefined; }
}
function uniq(components: DependencyComponent[]): DependencyComponent[] {
  const map = new Map<string, DependencyComponent>();
  for (const item of components) {
    const key = `${item.ecosystem}:${item.name.toLowerCase()}:${item.version}`;
    const previous = map.get(key);
    if (!previous || (!previous.direct && item.direct)) map.set(key, item);
  }
  return [...map.values()].sort((a,b)=>`${a.ecosystem}:${a.name}:${a.version}`.localeCompare(`${b.ecosystem}:${b.name}:${b.version}`));
}

function parsePackageLock(content: string): DependencyComponent[] {
  const lock = JSON.parse(content) as PackageLock;
  const components: DependencyComponent[] = [];
  if (lock.packages) {
    const root = lock.packages[''];
    const directNames = new Set([
      ...Object.keys(root?.dependencies ?? {}),
      ...Object.keys(root?.devDependencies ?? {}),
      ...Object.keys(root?.optionalDependencies ?? {})
    ].map((name)=>name.toLowerCase()));
    const byPath = new Map<string, { name:string; version:string; purl:string }>();
    for (const [packagePath, entry] of Object.entries(lock.packages)) {
      if (!packagePath || !entry.version) continue;
      const pathName = packagePath.split('node_modules/').at(-1);
      const name = entry.name ?? pathName;
      if (!name) continue;
      byPath.set(packagePath, {name, version:entry.version, purl:npmPurl(name,entry.version)});
    }
    for (const [packagePath, entry] of Object.entries(lock.packages)) {
      if (!packagePath || !entry.version) continue;
      const resolved = byPath.get(packagePath); if (!resolved) continue;
      const dependencies:string[]=[];
      for(const depName of Object.keys(entry.dependencies??{})){
        const dep=byPath.get(`node_modules/${depName}`) ?? [...byPath.entries()].find(([path])=>path.endsWith(`/node_modules/${depName}`))?.[1];
        if(dep)dependencies.push(dep.purl);
      }
      const hashes=sriHashes(entry.integrity);
      components.push({ ecosystem:'npm', name:resolved.name, version:resolved.version, direct:directNames.has(resolved.name.toLowerCase()), dev:Boolean(entry.dev), source:entry.resolved??'package-lock.json', purl:resolved.purl, packagePath, ...(entry.license?{license:entry.license}:{}), ...(hashes?{hashes}:{}), ...(dependencies.length?{dependencies}:{}) });
    }
  } else if (lock.dependencies) {
    const purls=new Map(Object.entries(lock.dependencies).filter(([,v])=>v.version).map(([name,v])=>[name,npmPurl(name,v.version!)]));
    for (const [name, entry] of Object.entries(lock.dependencies)) if (entry.version) {
      const hashes=sriHashes(entry.integrity); const dependencies=Object.keys(entry.requires??{}).map(n=>purls.get(n)).filter((v):v is string=>Boolean(v));
      components.push({ ecosystem:'npm', name, version:entry.version, direct:true, dev:Boolean(entry.dev), source:entry.resolved??'package-lock.json', purl:npmPurl(name,entry.version), ...(hashes?{hashes}:{}), ...(dependencies.length?{dependencies}:{}) });
    }
  }
  return components;
}
function parseRequirements(content: string, source: string): DependencyComponent[] {
  const components: DependencyComponent[]=[];
  for (const raw of content.split(/\r?\n/)) {
    const line=raw.trim(); if(!line||line.startsWith('#')||line.startsWith('-')) continue;
    const match=line.split(';')[0]!.trim().match(/^([A-Za-z0-9_.-]+)\s*==\s*([^\s]+)$/); if(!match) continue;
    components.push({ecosystem:'pypi',name:match[1]!,version:match[2]!,direct:true,dev:false,source,purl:pypiPurl(match[1]!,match[2]!)});
  }
  return components;
}
function parsePyproject(content: string): DependencyComponent[] {
  const components: DependencyComponent[]=[]; let inDependencies=false;
  for(const raw of content.split(/\r?\n/)){const line=raw.trim();if(line==='dependencies = ['||line.startsWith('dependencies=[')){inDependencies=true;continue;}if(inDependencies&&line.startsWith(']')){inDependencies=false;continue;}if(!inDependencies)continue;const quoted=line.match(/["']([^"']+)["']/)?.[1];if(!quoted)continue;const match=quoted.match(/^([A-Za-z0-9_.-]+)\s*==\s*([^\s;]+)$/);if(match)components.push({ecosystem:'pypi',name:match[1]!,version:match[2]!,direct:true,dev:false,source:'pyproject.toml',purl:pypiPurl(match[1]!,match[2]!)})}
  return components;
}
function pyprojectDependencyNames(content:string|undefined):Set<string>{
  const out=new Set<string>(); if(!content)return out; let section=''; let inPep621=false;
  const add=(spec:string)=>{const name=spec.trim().match(/^([A-Za-z0-9_.-]+)/)?.[1];if(name)out.add(name.toLowerCase());};
  for(const raw of content.split(/\r?\n/)){
    const line=raw.trim(); if(!line||line.startsWith('#'))continue;
    const header=line.match(/^\[([^\]]+)\]$/)?.[1]?.toLowerCase(); if(header){section=header;inPep621=false;continue;}
    if((section==='project'||section==='dependency-groups')&&/^dependencies\s*=\s*\[$/.test(line)){inPep621=true;continue;}
    if(inPep621&&line.startsWith(']')){inPep621=false;continue;}
    if(inPep621){const quoted=line.match(/["']([^"']+)["']/)?.[1];if(quoted)add(quoted);continue;}
    if(section==='tool.poetry.dependencies'||section==='tool.poetry.group.dev.dependencies'||section.startsWith('tool.poetry.group.')&&section.endsWith('.dependencies')){
      const m=line.match(/^([A-Za-z0-9_.-]+)\s*=/);if(m&&m[1]!.toLowerCase()!=='python')out.add(m[1]!.toLowerCase());
    }
  }
  return out;
}
function parsePoetryLock(content:string,directNames=new Set<string>()):DependencyComponent[]{
  const out:DependencyComponent[]=[]; for(const block of content.split(/\n(?=\[\[package\]\])/g)){if(!block.includes('[[package]]'))continue;const name=block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];const version=block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];const category=block.match(/^category\s*=\s*"([^"]+)"/m)?.[1];if(name&&version)out.push({ecosystem:'pypi',name,version,direct:directNames.has(name.toLowerCase()),dev:category==='dev',source:'poetry.lock',purl:pypiPurl(name,version)});} return out;
}
function parseUvLock(content:string,directNames=new Set<string>()):DependencyComponent[]{
  const out:DependencyComponent[]=[]; for(const block of content.split(/\n(?=\[\[package\]\])/g)){if(!block.includes('[[package]]'))continue;const name=block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];const version=block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];if(name&&version)out.push({ecosystem:'pypi',name,version,direct:directNames.has(name.toLowerCase()),dev:false,source:'uv.lock',purl:pypiPurl(name,version)});} return out;
}
function xmlValue(xml: string, tag: string): string | undefined {
  const m=xml.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i')); return m?.[1]?.trim();
}
function pomProperties(xml:string):Record<string,string>{
  const out:Record<string,string>={}; const block=xml.match(/<properties>([\s\S]*?)<\/properties>/i)?.[1]??'';
  for(const m of block.matchAll(/<([A-Za-z0-9_.-]+)>([^<]+)<\/\1>/g)) out[m[1]!]=m[2]!.trim();
  return out;
}
function resolveMavenVersion(value:string|undefined, props:Record<string,string>):string|undefined{
  if(!value)return undefined; const m=value.match(/^\$\{([^}]+)\}$/); return m ? props[m[1]!] : value;
}
interface MavenBom { coordinate:string; managed:Map<string,string>; imports:string[]; }
function pomCoordinates(content:string):string|undefined{
  const clean=content.replace(/<dependencies>[\s\S]*?<\/dependencies>/gi,'').replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/gi,'');
  const artifact=xmlValue(clean,'artifactId'); if(!artifact)return undefined;
  const parent=clean.match(/<parent>([\s\S]*?)<\/parent>/i)?.[1]??'';
  const withoutParent=clean.replace(/<parent>[\s\S]*?<\/parent>/i,'');
  const group=xmlValue(withoutParent,'groupId')??xmlValue(parent,'groupId');
  const version=xmlValue(withoutParent,'version')??xmlValue(parent,'version');
  return group&&version?`${group}:${artifact}:${version}`:undefined;
}
function pomManagement(content:string):MavenBom{
  const props=pomProperties(content); const managed=new Map<string,string>(); const imports:string[]=[];
  const management=content.match(/<dependencyManagement>([\s\S]*?)<\/dependencyManagement>/i)?.[1]??'';
  for(const m of management.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi)){
    const x=m[1]!; const group=xmlValue(x,'groupId'); const artifact=xmlValue(x,'artifactId'); const version=resolveMavenVersion(xmlValue(x,'version'),props);
    if(!group||!artifact||!version)continue;
    if((xmlValue(x,'type')??'').toLowerCase()==='pom'&&(xmlValue(x,'scope')??'').toLowerCase()==='import')imports.push(`${group}:${artifact}:${version}`);
    else managed.set(`${group}:${artifact}`,version);
  }
  return {coordinate:pomCoordinates(content)??'',managed,imports};
}
function resolveBomManagement(bom:MavenBom,local:Map<string,MavenBom>,seen=new Set<string>()):Map<string,string>{
  const out=new Map<string,string>();
  for(const coordinate of bom.imports){if(seen.has(coordinate))continue;const imported=local.get(coordinate);if(!imported)continue;const next=new Set(seen);next.add(coordinate);for(const [k,v] of resolveBomManagement(imported,local,next))out.set(k,v);for(const [k,v] of imported.managed)out.set(k,v);}
  for(const [k,v] of bom.managed)out.set(k,v); return out;
}
function parsePom(content:string, source='pom.xml', localBoms=new Map<string,MavenBom>()):DependencyComponent[]{
  const props=pomProperties(content); const components:DependencyComponent[]=[]; const own=pomManagement(content); const managed=resolveBomManagement(own,localBoms);
  const directContent=content.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/gi,'');
  for(const m of directContent.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi)){
    const x=m[1]!; const group=xmlValue(x,'groupId'); const artifact=xmlValue(x,'artifactId'); const scope=xmlValue(x,'scope')??'compile';
    if(!group||!artifact||scope==='test')continue; const name=`${group}:${artifact}`;
    const version=resolveMavenVersion(xmlValue(x,'version'),props)??managed.get(name); if(!version)continue;
    components.push({ecosystem:'maven',name,version,direct:true,dev:false,source,purl:mavenPurl(group,artifact,version)});
  }
  return components;
}
function parseGradleLock(content:string):DependencyComponent[]{
  const components:DependencyComponent[]=[];
  for(const raw of content.split(/\r?\n/)){const line=raw.trim();if(!line||line.startsWith('#')||line.startsWith('empty='))continue;const coord=line.split('=')[0]!.trim();const m=coord.match(/^([^:]+):([^:]+):([^:]+)$/);if(!m)continue;const [,group,artifact,version]=m;components.push({ecosystem:'maven',name:`${group}:${artifact}`,version:version!,direct:false,dev:false,source:'gradle.lockfile',purl:mavenPurl(group!,artifact!,version!)})}
  return components;
}
function parseGradleBuild(content:string):DependencyComponent[]{
  const components:DependencyComponent[]=[];
  const re=/(?:implementation|api|compileOnly|runtimeOnly)\s*(?:\(\s*)?["']([^:"']+):([^:"']+):([^"']+)["']/g;
  for(const m of content.matchAll(re)){const [,group,artifact,version]=m;components.push({ecosystem:'maven',name:`${group}:${artifact}`,version:version!,direct:true,dev:false,source:'build.gradle',purl:mavenPurl(group!,artifact!,version!)})}
  return components;
}
function parseCsproj(content:string, source='project.csproj'):DependencyComponent[]{
  const components:DependencyComponent[]=[];
  for(const m of content.matchAll(/<PackageReference\b([^>]*)\/?>(?:([\s\S]*?)<\/PackageReference>)?/gi)){
    const attrs=m[1]??''; const body=m[2]??''; const name=attrs.match(/\b(?:Include|Update)\s*=\s*["']([^"']+)["']/i)?.[1]; const version=attrs.match(/\bVersion\s*=\s*["']([^"']+)["']/i)?.[1]??xmlValue(body,'Version');
    if(name&&version)components.push({ecosystem:'nuget',name,version,direct:true,dev:false,source,purl:nugetPurl(name,version)});
  }
  return components;
}
function parseNugetLock(content:string):DependencyComponent[]{
  const parsed=JSON.parse(content) as {dependencies?:Record<string,Record<string,{type?:string,resolved?:string}>>}; const components:DependencyComponent[]=[];
  for(const framework of Object.values(parsed.dependencies??{})) for(const [name,entry] of Object.entries(framework)){
    if(!entry.resolved)continue; components.push({ecosystem:'nuget',name,version:entry.resolved,direct:entry.type==='Direct',dev:false,source:'packages.lock.json',purl:nugetPurl(name,entry.resolved)});
  }
  return components;
}
function parseProjectAssets(content:string):DependencyComponent[]{
  const parsed=JSON.parse(content) as {libraries?:Record<string,{type?:string,path?:string}>;project?:{frameworks?:Record<string,{dependencies?:Record<string,unknown>}>}}; const direct=new Set<string>();
  for(const fw of Object.values(parsed.project?.frameworks??{})) for(const name of Object.keys(fw.dependencies??{})) direct.add(name.toLowerCase());
  const components:DependencyComponent[]=[];
  for(const [key,entry] of Object.entries(parsed.libraries??{})){if(entry.type&&entry.type!=='package')continue;const slash=key.lastIndexOf('/');if(slash<1)continue;const name=key.slice(0,slash),version=key.slice(slash+1);components.push({ecosystem:'nuget',name,version,direct:direct.has(name.toLowerCase()),dev:false,source:'obj/project.assets.json',purl:nugetPurl(name,version),...(entry.path?{packagePath:entry.path}:{})})}
  return components;
}

function conanPurl(name:string,version:string):string{return `pkg:conan/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;}
function vcpkgPurl(name:string,version:string):string{return `pkg:vcpkg/${encodeURIComponent(name.toLowerCase())}@${encodeURIComponent(version)}`;}
function parseConanRef(ref:string,source:string,direct:boolean):DependencyComponent|undefined{
  const clean=ref.trim().replace(/^['\"]|['\"]$/g,'').split('#')[0]!.split('%')[0]!;
  const m=clean.match(/^([A-Za-z0-9_.+\-]+)\/([^@\s]+)(?:@[^\s]+)?$/); if(!m)return undefined;
  return {ecosystem:'conan',name:m[1]!,version:m[2]!,direct,dev:false,source,purl:conanPurl(m[1]!,m[2]!)};
}
function parseConanfileTxt(content:string):DependencyComponent[]{
  const out:DependencyComponent[]=[]; let section='';
  for(const raw of content.split(/\r?\n/)){const line=raw.trim(); if(!line||line.startsWith('#'))continue; if(/^\[[^\]]+\]$/.test(line)){section=line.toLowerCase();continue;} if(section==='[requires]'||section==='[tool_requires]'||section==='[build_requires]'){const c=parseConanRef(line,'conanfile.txt',true); if(c)out.push({...c,dev:section!=='[requires]'});}}
  return out;
}
function parseConanfilePy(content:string):DependencyComponent[]{
  const out:DependencyComponent[]=[];
  for(const m of content.matchAll(/\b(requires|tool_requires)\s*=\s*(?:\(([\s\S]*?)\)|\[([\s\S]*?)\])/g)){
    const body=m[2]??m[3]??''; for(const q of body.matchAll(/[\"']([^\"']+)[\"']/g)){const c=parseConanRef(q[1]!,'conanfile.py',true);if(c)out.push({...c,dev:m[1]==='tool_requires'})}
  }
  for(const m of content.matchAll(/self\.(requires|tool_requires)\s*\(\s*[\"']([^\"']+)[\"']/g)){const c=parseConanRef(m[2]!,'conanfile.py',true);if(c)out.push({...c,dev:m[1]==='tool_requires'})}
  return out;
}
function parseConanLock(content:string):DependencyComponent[]{
  const out:DependencyComponent[]=[]; let value:unknown; try{value=JSON.parse(content)}catch{return out}
  const walk=(x:unknown)=>{if(Array.isArray(x)){for(const v of x)walk(v);return;} if(!x||typeof x!=='object')return; for(const [k,v] of Object.entries(x as Record<string,unknown>)){if((k==='ref'||k==='reference')&&typeof v==='string'){const c=parseConanRef(v,'conan.lock',false);if(c)out.push(c)} else walk(v)}}; walk(value); return out;
}
function vcpkgVersion(x:Record<string,unknown>):string|undefined{
  for(const k of ['version','version-string','version-semver','version-date'])if(typeof x[k]==='string'&&x[k])return x[k] as string; return undefined;
}
function parseVcpkgManifest(content:string):DependencyComponent[]{
  let x:Record<string,unknown>;try{x=JSON.parse(content) as Record<string,unknown>}catch{return []} const out:DependencyComponent[]=[];
  for(const item of Array.isArray(x.dependencies)?x.dependencies:[]){if(typeof item==='string')continue;if(!item||typeof item!=='object'||Array.isArray(item))continue;const o=item as Record<string,unknown>;const name=typeof o.name==='string'?o.name:undefined;const version=vcpkgVersion(o);if(name&&version)out.push({ecosystem:'vcpkg',name,version,direct:true,dev:false,source:'vcpkg.json',purl:vcpkgPurl(name,version)});} return out;
}
function parseVcpkgLock(content:string):DependencyComponent[]{
  let x:unknown;try{x=JSON.parse(content)}catch{return []} const out:DependencyComponent[]=[];
  const walk=(v:unknown)=>{if(Array.isArray(v)){for(const a of v)walk(a);return;}if(!v||typeof v!=='object')return;const o=v as Record<string,unknown>;const name=typeof o.name==='string'?o.name:typeof o.package==='string'?o.package:undefined;const version=vcpkgVersion(o);if(name&&version)out.push({ecosystem:'vcpkg',name,version,direct:false,dev:false,source:'vcpkg-lock.json',purl:vcpkgPurl(name,version)});for(const c of Object.values(o))if(typeof c==='object')walk(c)};walk(x);return out;
}

function parseVcpkgStatus(content:string):DependencyComponent[]{
  const out:DependencyComponent[]=[];
  for(const block of content.split(/\r?\n\r?\n/)){
    const fields:Record<string,string>={};
    for(const raw of block.split(/\r?\n/)){const m=raw.match(/^([A-Za-z0-9-]+):\s*(.+)$/);if(m)fields[m[1]!.toLowerCase()]=m[2]!.trim();}
    const name=fields.package, version=fields.version; if(!name||!version)continue;
    out.push({ecosystem:'vcpkg',name,version,direct:false,dev:false,source:'vcpkg_installed/vcpkg/status',purl:vcpkgPurl(name,version)});
  }
  return out;
}


function cargoWorkspaceDependencies(content:string):Map<string,string>{
  const out=new Map<string,string>(); let section='';
  for(const raw of content.split(/\r?\n/)){const line=raw.trim();const header=line.match(/^\[([^\]]+)\]$/)?.[1]?.toLowerCase();if(header){section=header;continue}if(section!=='workspace.dependencies')continue;const m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);if(!m)continue;const alias=m[1]!,spec=m[2]!;const actual=spec.match(/\bpackage\s*=\s*["']([^"']+)["']/)?.[1]??alias;out.set(alias.toLowerCase(),actual.toLowerCase());}
  return out;
}
function cargoDependencyNames(manifests:string[]):{runtime:Set<string>;dev:Set<string>}{
  const runtime=new Set<string>(),dev=new Set<string>(); const workspace=new Map<string,string>();
  for(const content of manifests)for(const [k,v] of cargoWorkspaceDependencies(content))workspace.set(k,v);
  for(const content of manifests){let section='';for(const raw of content.split(/\r?\n/)){const line=raw.trim();if(!line||line.startsWith('#'))continue;const h=line.match(/^\[([^\]]+)\]$/)?.[1]?.toLowerCase();if(h){section=h;continue}if(!['dependencies','dev-dependencies','build-dependencies'].includes(section))continue;const m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);if(!m)continue;const alias=m[1]!,spec=m[2]!;const actual=(spec.match(/\bpackage\s*=\s*["']([^"']+)["']/)?.[1]??(spec.includes('workspace')?workspace.get(alias.toLowerCase()):undefined)??alias).toLowerCase();(section==='dev-dependencies'||section==='build-dependencies'?dev:runtime).add(actual);}}
  return {runtime,dev};
}
function parseCargoLock(content:string,manifests:string[]=[]):DependencyComponent[]{
  const direct=manifests.length?cargoDependencyNames(manifests):{runtime:new Set<string>(),dev:new Set<string>()};
  const raw:Array<{name:string;version:string;source:string;checksum?:string;deps:Array<{name:string;version?:string}>}>=[];
  for(const block of content.split(/\n(?=\[\[package\]\])/g)){
    if(!block.includes('[[package]]'))continue; const name=block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1]; const version=block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    const source=block.match(/^\s*source\s*=\s*"([^"]+)"/m)?.[1]??'Cargo.lock'; const checksum=block.match(/^\s*checksum\s*=\s*"([a-fA-F0-9]+)"/m)?.[1]; if(!name||!version)continue;
    const deps:Array<{name:string;version?:string}>=[]; const depBlock=block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/m)?.[1]??'';
    for(const m of depBlock.matchAll(/"([^" ]+)(?:\s+([^" ]+))?(?:\s+\([^)]*\))?"/g))deps.push({name:m[1]!,...(m[2]?{version:m[2]}:{})});
    raw.push({name,version,source,...(checksum?{checksum}:{}),deps});
  }
  const lookup=(name:string,version?:string)=>raw.find(x=>x.name===name&&(!version||x.version===version));
  return raw.map(x=>{const key=x.name.toLowerCase();const dependencies=x.deps.map(d=>lookup(d.name,d.version)).filter((v):v is typeof raw[number]=>Boolean(v)).map(d=>cargoPurl(d.name,d.version));return {ecosystem:'cargo' as const,name:x.name,version:x.version,direct:direct.runtime.has(key)||direct.dev.has(key),dev:direct.dev.has(key)&&!direct.runtime.has(key),source:x.source,purl:cargoPurl(x.name,x.version),...(x.checksum?{hashes:[{algorithm:'SHA-256' as const,value:x.checksum}]}:{}),...(dependencies.length?{dependencies}:{})};});
}
function parseCargoTomlExact(content:string):DependencyComponent[]{
  const out:DependencyComponent[]=[]; let section='';
  for(const raw of content.split(/\r?\n/)){
    const line=raw.trim(); const s=line.match(/^\[([^\]]+)\]$/)?.[1]?.toLowerCase(); if(s){section=s;continue}
    if(!['dependencies','dev-dependencies','build-dependencies'].includes(section))continue;
    const m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(?:"=([^"]+)"|\{\s*version\s*=\s*"=([^"]+)")/); if(!m)continue;
    const name=m[1]!,version=(m[2]??m[3])!; out.push({ecosystem:'cargo',name,version,direct:true,dev:section!=='dependencies',source:'Cargo.toml',purl:cargoPurl(name,version)});
  }
  return out;
}
function goSumHashes(content:string|undefined):Map<string,DependencyComponent['hashes']>{
  const out=new Map<string,DependencyComponent['hashes']>();if(!content)return out;
  for(const raw of content.split(/\r?\n/)){const m=raw.trim().match(/^(\S+)\s+(v\S+)\s+h1:([A-Za-z0-9+/=]+)$/);if(!m||m[2]!.endsWith('/go.mod'))continue;try{out.set(`${m[1]}@${m[2]}`,[{algorithm:'SHA-256',value:Buffer.from(m[3]!,'base64').toString('hex')}]);}catch{}}
  return out;
}
function parseGoMod(content:string,sumContent?:string,source='go.mod'):DependencyComponent[]{
  const required:Array<{name:string;version:string;direct:boolean}>=[]; const excluded=new Set<string>(); const replacements=new Map<string,{name:string;oldVersion?:string;version?:string;local:boolean}>(); let mode:''|'require'|'exclude'|'replace'='';
  for(const raw of content.split(/\r?\n/)){
    const line=raw.trim(); if(!line||line.startsWith('//'))continue;
    const open=line.match(/^(require|exclude|replace)\s*\($/); if(open){mode=open[1] as typeof mode;continue} if(mode&&line===')'){mode='';continue}
    const body=mode?line:line.replace(/^(require|exclude|replace)\s+/,''); const directive=mode||line.match(/^(require|exclude|replace)\s+/)?.[1] as typeof mode; if(!directive)continue;
    if(directive==='require'){const m=body.match(/^(\S+)\s+(v\S+)(?:\s+\/\/\s*indirect)?$/);if(m)required.push({name:m[1]!,version:m[2]!,direct:!/\/\/\s*indirect/.test(raw)});}
    else if(directive==='exclude'){const m=body.match(/^(\S+)\s+(v\S+)$/);if(m)excluded.add(`${m[1]}@${m[2]}`);}
    else {const m=body.match(/^(\S+?)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?$/);if(m){const key=`${m[1]}@${m[2]??'*'}`;replacements.set(key,{name:m[3]!,...(m[2]?{oldVersion:m[2]}:{}),...(m[4]?{version:m[4]}:{}),local:!m[4]});}}
  }
  const sums=goSumHashes(sumContent); const out:DependencyComponent[]=[];
  for(const req of required){if(excluded.has(`${req.name}@${req.version}`))continue;const replacement=replacements.get(`${req.name}@${req.version}`)??replacements.get(`${req.name}@*`);const name=replacement?.name??req.name;const version=replacement?.version??req.version;const hashes=sums.get(`${name}@${version}`)??(!replacement?sums.get(`${req.name}@${req.version}`):undefined);const detail=replacement?`${source} replace ${req.name}${replacement.oldVersion?` ${replacement.oldVersion}`:''} => ${replacement.name}${replacement.version?` ${replacement.version}`:''}`:source;out.push({ecosystem:'go',name,version,direct:req.direct,dev:false,source:detail,purl:goPurl(name,version),...(replacement?{replacedFrom:`${req.name}@${req.version}`}:{}) ,...(hashes?{hashes}:{})});}
  return out;
}


export function parseDependencyFiles(files:Record<string,string>,generatedAt:string):DependencySnapshot{
  const c:DependencyComponent[]=[]; const entries=Object.entries(files).map(([name,content])=>[name.replace(/\\/g,'/'),content] as const);
  const byBase=(base:string)=>entries.filter(([name])=>basename(name).toLowerCase()===base.toLowerCase());
  const sameDir=(path:string,base:string)=>entries.find(([name])=>dirname(name)===dirname(path)&&basename(name).toLowerCase()===base.toLowerCase())?.[1];
  for(const [name,content] of byBase('package-lock.json'))c.push(...parsePackageLock(content).map(x=>({...x,source:x.source==='package-lock.json'?name:x.source})));
  for(const [name,content] of entries.filter(([n])=>/requirements(?:\.[^/]+)?\.txt$/i.test(basename(n))))c.push(...parseRequirements(content,name));
  for(const [name,content] of byBase('pyproject.toml'))c.push(...parsePyproject(content).map(x=>({...x,source:name})));
  for(const [name,content] of byBase('poetry.lock'))c.push(...parsePoetryLock(content,pyprojectDependencyNames(sameDir(name,'pyproject.toml'))).map(x=>({...x,source:name})));
  for(const [name,content] of byBase('uv.lock'))c.push(...parseUvLock(content,pyprojectDependencyNames(sameDir(name,'pyproject.toml'))).map(x=>({...x,source:name})));
  const localBoms=new Map<string,MavenBom>();for(const [,content] of byBase('pom.xml')){const bom=pomManagement(content);if(bom.coordinate)localBoms.set(bom.coordinate,bom);}for(const [name,content] of byBase('pom.xml'))c.push(...parsePom(content,name,localBoms));
  for(const [,content] of byBase('gradle.lockfile'))c.push(...parseGradleLock(content));
  for(const [,content] of [...byBase('build.gradle'),...byBase('build.gradle.kts')])c.push(...parseGradleBuild(content));
  for(const [,content] of byBase('packages.lock.json'))c.push(...parseNugetLock(content));
  for(const [name,content] of entries.filter(([n])=>n.endsWith('obj/project.assets.json')))c.push(...parseProjectAssets(content).map(x=>({...x,source:name})));
  for(const [,content] of byBase('conanfile.txt'))c.push(...parseConanfileTxt(content)); for(const [,content] of byBase('conanfile.py'))c.push(...parseConanfilePy(content)); for(const [,content] of byBase('conan.lock'))c.push(...parseConanLock(content));
  for(const [,content] of byBase('vcpkg.json'))c.push(...parseVcpkgManifest(content)); for(const [,content] of byBase('vcpkg-lock.json'))c.push(...parseVcpkgLock(content)); for(const [,content] of entries.filter(([n])=>n.endsWith('vcpkg_installed/vcpkg/status')))c.push(...parseVcpkgStatus(content));
  const cargoLocks=byBase('Cargo.lock');
  for(const [lockPath,lock] of cargoLocks){const root=dirname(lockPath);const manifests=byBase('Cargo.toml').filter(([manifestPath])=>{if(!(manifestPath===`${root}/Cargo.toml`||root==='.'&&manifestPath==='Cargo.toml'||manifestPath.startsWith(`${root}/`)))return false;const nestedLock=cargoLocks.find(([candidate])=>candidate!==lockPath&&manifestPath.startsWith(`${dirname(candidate)}/`));return !nestedLock;}).map(([,content])=>content);c.push(...parseCargoLock(lock,manifests).map(x=>({...x,source:x.source==='Cargo.lock'?lockPath:x.source})));}
  if(!cargoLocks.length)for(const [,m] of byBase('Cargo.toml'))c.push(...parseCargoTomlExact(m));
  for(const [name,content] of byBase('go.mod'))c.push(...parseGoMod(content,sameDir(name,'go.sum'),name));
  for(const [name,content] of entries)if(name.toLowerCase().endsWith('.csproj'))c.push(...parseCsproj(content,name));
  const directVcpkg=new Set<string>(); for(const [,content] of byBase('vcpkg.json'))try{const manifest=JSON.parse(content) as {dependencies?:unknown[]};for(const item of manifest.dependencies??[]){if(typeof item==='string')directVcpkg.add(item.toLowerCase());else if(item&&typeof item==='object'&&!Array.isArray(item)&&typeof (item as Record<string,unknown>).name==='string')directVcpkg.add(((item as Record<string,unknown>).name as string).toLowerCase());}}catch{}
  for(let i=0;i<c.length;i++)if(c[i]?.ecosystem==='vcpkg'&&directVcpkg.has(c[i]!.name.toLowerCase()))c[i]={...c[i]!,direct:true};
  return {generatedAt,components:uniq(c)};
}

const DISCOVERY_NAMES=['package-lock.json','requirements.txt','requirements.lock','pyproject.toml','poetry.lock','uv.lock','pom.xml','gradle.lockfile','build.gradle','build.gradle.kts','packages.lock.json','obj/project.assets.json','conanfile.txt','conanfile.py','conan.lock','vcpkg.json','vcpkg-lock.json','vcpkg_installed/vcpkg/status','Cargo.toml','Cargo.lock','go.mod','go.sum'];
export function isDependencyInputPath(path:string):boolean{const n=path.replace(/\\/g,'/');const b=basename(n).toLowerCase();return DISCOVERY_NAMES.some(x=>n.toLowerCase().endsWith(x.toLowerCase()))||b.endsWith('.csproj')||/^requirements(?:\.[^/]+)?\.txt$/i.test(b);}

async function collectDependencyFiles(base:string,current=base,out:Record<string,string>={}):Promise<Record<string,string>>{
  let entries; try{entries=await readdir(current,{withFileTypes:true})}catch{return out} for(const entry of entries){if(['.git','node_modules','dist','build','.venv','venv'].includes(entry.name))continue;const full=join(current,entry.name);if(entry.isDirectory()){await collectDependencyFiles(base,full,out);continue}const rel=full.slice(base.length+1).replace(/\\/g,'/');if(isDependencyInputPath(rel)){const v=await maybeRead(full);if(v!==undefined)out[rel]=v;}}return out;
}
export async function discoverDependencies(root:string,generatedAt=new Date().toISOString(),serviceRoot=''):Promise<DependencySnapshot>{const base=serviceRoot?resolve(root,serviceRoot):root;return parseDependencyFiles(await collectDependencyFiles(base),generatedAt);}

