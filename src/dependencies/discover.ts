import { readFile, readdir } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import type { DependencyComponent, DependencySnapshot } from '../core/types.js';

interface PackageLock {
  packages?: Record<string, { name?: string; version?: string; dev?: boolean; resolved?: string; license?: string }>;
  dependencies?: Record<string, { version?: string; dev?: boolean; resolved?: string }>;
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
    for (const [packagePath, entry] of Object.entries(lock.packages)) {
      if (!packagePath || !entry.version) continue;
      const pathName = packagePath.split('node_modules/').at(-1);
      const name = entry.name ?? pathName;
      if (!name) continue;
      components.push({ ecosystem:'npm', name, version:entry.version, direct:packagePath.startsWith('node_modules/')&&!packagePath.slice('node_modules/'.length).includes('/node_modules/'), dev:Boolean(entry.dev), source:entry.resolved??'package-lock.json', purl:npmPurl(name,entry.version), packagePath, ...(entry.license?{license:entry.license}:{}) });
    }
  } else if (lock.dependencies) {
    for (const [name, entry] of Object.entries(lock.dependencies)) if (entry.version) components.push({ ecosystem:'npm', name, version:entry.version, direct:true, dev:Boolean(entry.dev), source:entry.resolved??'package-lock.json', purl:npmPurl(name,entry.version) });
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
function parsePom(content:string):DependencyComponent[]{
  const props=pomProperties(content); const components:DependencyComponent[]=[];
  const depBlock=content.match(/<dependencies>([\s\S]*?)<\/dependencies>/gi)??[];
  for(const block of depBlock){
    for(const m of block.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi)){
      const x=m[1]!; const group=xmlValue(x,'groupId'); const artifact=xmlValue(x,'artifactId'); const version=resolveMavenVersion(xmlValue(x,'version'),props); const scope=xmlValue(x,'scope')??'compile';
      if(!group||!artifact||!version||scope==='test')continue;
      const name=`${group}:${artifact}`;
      components.push({ecosystem:'maven',name,version,direct:true,dev:false,source:'pom.xml',purl:mavenPurl(group,artifact,version)});
    }
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


function cargoDependencyNames(content:string):{runtime:Set<string>;dev:Set<string>}{
  const runtime=new Set<string>(),dev=new Set<string>(); let section='';
  for(const raw of content.split(/\r?\n/)){
    const line=raw.trim(); if(!line||line.startsWith('#'))continue;
    const s=line.match(/^\[([^\]]+)\]$/)?.[1]?.toLowerCase(); if(s){section=s;continue}
    if(!['dependencies','dev-dependencies','build-dependencies'].includes(section))continue;
    const m=line.match(/^([A-Za-z0-9_.-]+)\s*=/); if(!m)continue;
    (section==='dev-dependencies'||section==='build-dependencies'?dev:runtime).add(m[1]!.toLowerCase());
  }
  return {runtime,dev};
}
function parseCargoLock(content:string,manifest?:string):DependencyComponent[]{
  const direct=manifest?cargoDependencyNames(manifest):{runtime:new Set<string>(),dev:new Set<string>()};
  const out:DependencyComponent[]=[];
  for(const block of content.split(/\n(?=\[\[package\]\])/g)){
    if(!block.includes('[[package]]'))continue;
    const name=block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version=block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    const source=block.match(/^\s*source\s*=\s*"([^"]+)"/m)?.[1]??'Cargo.lock';
    if(!name||!version)continue;
    const key=name.toLowerCase();
    out.push({ecosystem:'cargo',name,version,direct:direct.runtime.has(key)||direct.dev.has(key),dev:direct.dev.has(key)&&!direct.runtime.has(key),source,purl:cargoPurl(name,version)});
  }
  return out;
}
function parseCargoTomlExact(content:string):DependencyComponent[]{
  const names=cargoDependencyNames(content); const out:DependencyComponent[]=[]; let section='';
  for(const raw of content.split(/\r?\n/)){
    const line=raw.trim(); const s=line.match(/^\[([^\]]+)\]$/)?.[1]?.toLowerCase(); if(s){section=s;continue}
    if(!['dependencies','dev-dependencies','build-dependencies'].includes(section))continue;
    const m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(?:"=([^"]+)"|\{\s*version\s*=\s*"=([^"]+)")/); if(!m)continue;
    const name=m[1]!,version=(m[2]??m[3])!; out.push({ecosystem:'cargo',name,version,direct:true,dev:section!=='dependencies',source:'Cargo.toml',purl:cargoPurl(name,version)});
  }
  return out;
}
function parseGoMod(content:string):DependencyComponent[]{
  const out:DependencyComponent[]=[]; let inRequire=false;
  for(const raw of content.split(/\r?\n/)){
    let line=raw.trim(); if(!line||line.startsWith('//'))continue;
    if(/^require\s*\($/.test(line)){inRequire=true;continue}
    if(inRequire&&line===')'){inRequire=false;continue}
    if(!inRequire){
      const single=line.match(/^require\s+([^\s]+)\s+([^\s]+)(?:\s+\/\/\s+indirect)?$/);
      if(!single)continue; line=`${single[1]} ${single[2]}${/\/\/\s*indirect/.test(raw)?' // indirect':''}`;
    }
    const m=line.match(/^([^\s]+)\s+(v[^\s]+)(?:\s+\/\/\s+indirect)?$/); if(!m)continue;
    const indirect=/\/\/\s*indirect/.test(raw)||/\/\/\s*indirect/.test(line);
    out.push({ecosystem:'go',name:m[1]!,version:m[2]!,direct:!indirect,dev:false,source:'go.mod',purl:goPurl(m[1]!,m[2]!)});
  }
  return out;
}

export function parseDependencyFiles(files:Record<string,string>,generatedAt:string):DependencySnapshot{
  const c:DependencyComponent[]=[];
  if(files['package-lock.json'])c.push(...parsePackageLock(files['package-lock.json']));
  if(files['requirements.txt'])c.push(...parseRequirements(files['requirements.txt'],'requirements.txt'));
  if(files['pyproject.toml'])c.push(...parsePyproject(files['pyproject.toml']));
  if(files['pom.xml'])c.push(...parsePom(files['pom.xml']));
  if(files['gradle.lockfile'])c.push(...parseGradleLock(files['gradle.lockfile']));
  if(files['build.gradle'])c.push(...parseGradleBuild(files['build.gradle']));
  if(files['build.gradle.kts'])c.push(...parseGradleBuild(files['build.gradle.kts']));
  if(files['packages.lock.json'])c.push(...parseNugetLock(files['packages.lock.json']));
  if(files['obj/project.assets.json'])c.push(...parseProjectAssets(files['obj/project.assets.json']));
  if(files['conanfile.txt'])c.push(...parseConanfileTxt(files['conanfile.txt']));
  if(files['conanfile.py'])c.push(...parseConanfilePy(files['conanfile.py']));
  if(files['conan.lock'])c.push(...parseConanLock(files['conan.lock']));
  if(files['vcpkg.json'])c.push(...parseVcpkgManifest(files['vcpkg.json']));
  if(files['vcpkg-lock.json'])c.push(...parseVcpkgLock(files['vcpkg-lock.json']));
  if(files['vcpkg_installed/vcpkg/status'])c.push(...parseVcpkgStatus(files['vcpkg_installed/vcpkg/status']));
  if(files['Cargo.lock'])c.push(...parseCargoLock(files['Cargo.lock'],files['Cargo.toml']));
  else if(files['Cargo.toml'])c.push(...parseCargoTomlExact(files['Cargo.toml']));
  if(files['go.mod'])c.push(...parseGoMod(files['go.mod']));
  if(files['vcpkg.json']){
    try{
      const manifest=JSON.parse(files['vcpkg.json']) as {dependencies?:unknown[]};
      const directNames=new Set<string>();
      for(const item of manifest.dependencies??[]){
        if(typeof item==='string')directNames.add(item.toLowerCase());
        else if(item&&typeof item==='object'&&!Array.isArray(item)&&typeof (item as Record<string,unknown>).name==='string')directNames.add(((item as Record<string,unknown>).name as string).toLowerCase());
      }
      for(let i=0;i<c.length;i+=1)if(c[i]?.ecosystem==='vcpkg'&&directNames.has(c[i]!.name.toLowerCase()))c[i]={...c[i]!,direct:true};
    }catch{}
  }
  for(const [name,content] of Object.entries(files)) if(name.endsWith('.csproj')) c.push(...parseCsproj(content,name));
  return {generatedAt,components:uniq(c)};
}

export async function discoverDependencies(root:string,generatedAt=new Date().toISOString(),serviceRoot=''):Promise<DependencySnapshot>{
  const files:Record<string,string>={}; const base=serviceRoot?resolve(root,serviceRoot):root;
  for(const name of ['package-lock.json','requirements.txt','pyproject.toml','pom.xml','gradle.lockfile','build.gradle','build.gradle.kts','packages.lock.json','obj/project.assets.json','conanfile.txt','conanfile.py','conan.lock','vcpkg.json','vcpkg-lock.json','vcpkg_installed/vcpkg/status','Cargo.toml','Cargo.lock','go.mod','go.sum']){
    const value=await maybeRead(join(base,name)); if(value!==undefined)files[name]=value;
  }
  try{for(const entry of await readdir(base,{withFileTypes:true}))if(entry.isFile()&&entry.name.toLowerCase().endsWith('.csproj'))files[entry.name]=await readFile(join(base,entry.name),'utf8')}catch{}
  return parseDependencyFiles(files,generatedAt);
}
