import { readFile, readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { DependencyComponent } from '../core/types.js';

async function json(path:string):Promise<Record<string,unknown>|null>{try{return JSON.parse(await readFile(path,'utf8')) as Record<string,unknown>}catch{return null}}
async function text(path:string):Promise<string|undefined>{try{return await readFile(path,'utf8')}catch{return undefined}}
function npmPackagePath(root:string,serviceRoot:string,component:DependencyComponent):string{const packagePath=component.packagePath?.replace(/\\/g,'/')??`node_modules/${component.name}`;return resolve(root,serviceRoot,packagePath,'package.json')}
function xmlLicense(content:string):string|undefined{
  const block=content.match(/<licenses>([\s\S]*?)<\/licenses>/i)?.[1]??content;
  return block.match(/<license>[\s\S]*?<name>([^<]+)<\/name>[\s\S]*?<\/license>/i)?.[1]?.trim()
    ?? block.match(/<licenseUrl>([^<]+)<\/licenseUrl>/i)?.[1]?.trim()
    ?? block.match(/<license>([^<]+)<\/license>/i)?.[1]?.trim();
}
async function mavenLicense(component:DependencyComponent):Promise<string|undefined>{
  const [group,artifact]=component.name.split(':'); if(!group||!artifact)return undefined;
  const path=resolve(homedir(),'.m2','repository',...group.split('.'),artifact,component.version,`${artifact}-${component.version}.pom`);
  const content=await text(path); return content?xmlLicense(content):undefined;
}
async function nugetLicense(component:DependencyComponent):Promise<string|undefined>{
  const dir=resolve(homedir(),'.nuget','packages',component.name.toLowerCase(),component.version.toLowerCase());
  try{for(const e of await readdir(dir))if(e.toLowerCase().endsWith('.nuspec')){const content=await text(resolve(dir,e));if(content){const license=xmlLicense(content);if(license)return license}}}catch{}
  return undefined;
}
/** Enrich package metadata from local package caches/manifests. No package content leaves the machine. */
export async function enrichDependencyMetadata(root:string,components:DependencyComponent[],options:{serviceRoot?:string;offline?:boolean}={}):Promise<DependencyComponent[]>{
  const serviceRoot=options.serviceRoot??''; const result:DependencyComponent[]=[];
  for(const component of components){
    if(component.license){result.push(component);continue}
    let license:string|undefined;
    if(component.ecosystem==='npm'){const manifest=await json(npmPackagePath(root,serviceRoot,component)); license=typeof manifest?.license==='string'?manifest.license:undefined}
    else if(component.ecosystem==='maven')license=await mavenLicense(component);
    else if(component.ecosystem==='nuget')license=await nugetLicense(component);
    result.push(license?{...component,license}:component);
  }
  return result;
}
