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
  for(const [name,content] of Object.entries(files)) if(name.endsWith('.csproj')) c.push(...parseCsproj(content,name));
  return {generatedAt,components:uniq(c)};
}

export async function discoverDependencies(root:string,generatedAt=new Date().toISOString(),serviceRoot=''):Promise<DependencySnapshot>{
  const files:Record<string,string>={}; const base=serviceRoot?resolve(root,serviceRoot):root;
  for(const name of ['package-lock.json','requirements.txt','pyproject.toml','pom.xml','gradle.lockfile','build.gradle','build.gradle.kts','packages.lock.json','obj/project.assets.json']){
    const value=await maybeRead(join(base,name)); if(value!==undefined)files[name]=value;
  }
  try{for(const entry of await readdir(base,{withFileTypes:true}))if(entry.isFile()&&entry.name.toLowerCase().endsWith('.csproj'))files[entry.name]=await readFile(join(base,entry.name),'utf8')}catch{}
  return parseDependencyFiles(files,generatedAt);
}
