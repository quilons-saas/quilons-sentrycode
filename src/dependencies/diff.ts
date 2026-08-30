import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { DependencyChange, DependencyComponent, DependencySnapshot } from '../core/types.js';
import { compareVersions } from './versions.js';
import { isDependencyInputPath, parseDependencyFiles } from './discover.js';

const execFileAsync = promisify(execFile);

function key(component: DependencyComponent): string { return `${component.ecosystem}:${component.name.toLowerCase()}`; }

export function diffDependencies(before: DependencySnapshot, after: DependencySnapshot): DependencyChange[] {
  const group=(components:DependencyComponent[])=>{const out=new Map<string,DependencyComponent[]>();for(const c of components){const k=key(c);out.set(k,[...(out.get(k)??[]),c]);}return out;};
  const beforeGroups=group(before.components),afterGroups=group(after.components);const keys=new Set([...beforeGroups.keys(),...afterGroups.keys()]);const changes:DependencyChange[]=[];
  for(const itemKey of [...keys].sort()){
    const oldItems=beforeGroups.get(itemKey)??[],newItems=afterGroups.get(itemKey)??[];const oldByVersion=new Map(oldItems.map(c=>[c.version,c])),newByVersion=new Map(newItems.map(c=>[c.version,c]));
    const removed=oldItems.filter(c=>!newByVersion.has(c.version)),added=newItems.filter(c=>!oldByVersion.has(c.version));
    if(oldItems.length===1&&newItems.length===1&&removed.length===1&&added.length===1){const oldValue=oldItems[0]!,newValue=newItems[0]!;const comparison=compareVersions(newValue.version,oldValue.version);changes.push({kind:comparison>0?'upgraded':comparison<0?'downgraded':'changed',ecosystem:newValue.ecosystem,name:newValue.name,before:oldValue,after:newValue});continue;}
    for(const oldValue of removed)changes.push({kind:'removed',ecosystem:oldValue.ecosystem,name:oldValue.name,before:oldValue});
    for(const newValue of added)changes.push({kind:'added',ecosystem:newValue.ecosystem,name:newValue.name,after:newValue});
    for(const version of [...oldByVersion.keys()].filter(v=>newByVersion.has(v))){const oldValue=oldByVersion.get(version)!,newValue=newByVersion.get(version)!;if(oldValue.source!==newValue.source||oldValue.replacedFrom!==newValue.replacedFrom)changes.push({kind:'changed',ecosystem:newValue.ecosystem,name:newValue.name,before:oldValue,after:newValue});}
  }
  return changes;
}

async function gitShow(root: string, ref: string, path: string): Promise<string | undefined> {
  try { return (await execFileAsync('git', ['-C', root, 'show', `${ref}:${path}`], { encoding: 'utf8', maxBuffer: 20_000_000 })).stdout; }
  catch { return undefined; }
}

async function dependencyPathsAtRef(root:string, ref:string):Promise<string[]> {
  const {stdout}=await execFileAsync('git',['-C',root,'ls-tree','-r','--name-only',ref],{encoding:'utf8',maxBuffer:20_000_000});
  return stdout.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).filter(isDependencyInputPath).sort();
}

export async function dependencySnapshotAtRef(root: string, ref: string, generatedAt = new Date().toISOString()): Promise<DependencySnapshot> {
  const files: Record<string, string> = {};
  for (const name of await dependencyPathsAtRef(root,ref)) {
    const content = await gitShow(root, ref, name);
    if (content !== undefined) files[name] = content;
  }
  return parseDependencyFiles(files, generatedAt);
}
