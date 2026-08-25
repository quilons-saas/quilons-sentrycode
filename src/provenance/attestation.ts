import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import type { RepositoryContext } from '../core/types.js';

export interface ArtifactDigest { path:string; name:string; size:number; sha256:string; }
export interface ProvenanceStatement { _type:'https://in-toto.io/Statement/v1'; subject:Array<{name:string;digest:{sha256:string}}>; predicateType:'https://slsa.dev/provenance/v1'; predicate:Record<string,unknown>; }
export interface SignedAttestation { schemaVersion:1; algorithm:'none'|'sha256WithKey'; statement:ProvenanceStatement; signature?:string; publicKeyFingerprint?:string; }
async function digest(path:string):Promise<ArtifactDigest>{ const data=await readFile(path); const info=await stat(path); return {path,name:basename(path),size:info.size,sha256:createHash('sha256').update(data).digest('hex')}; }
export async function collectArtifacts(root:string,paths:string[]):Promise<ArtifactDigest[]>{ const out=[]; for(const p of paths) out.push(await digest(resolve(root,p))); return out; }
export function buildStatement(repository:RepositoryContext,artifacts:ArtifactDigest[],now=new Date()):ProvenanceStatement{
  return {_type:'https://in-toto.io/Statement/v1',subject:artifacts.map(a=>({name:a.path,digest:{sha256:a.sha256}})),predicateType:'https://slsa.dev/provenance/v1',predicate:{buildDefinition:{buildType:'https://quilons.ai/sentrycode/local-build/v1',externalParameters:{repository:repository.repository,branch:repository.branch}},runDetails:{builder:{id:`sentrycode:${process.version}`},metadata:{invocationId:`${repository.commitSha ?? 'uncommitted'}:${now.toISOString()}`,startedOn:now.toISOString(),finishedOn:now.toISOString()}},source:{commitSha:repository.commitSha,dirty:repository.isDirty}}};
}
export async function signStatement(statement:ProvenanceStatement,privateKeyPath?:string):Promise<SignedAttestation>{
  if(!privateKeyPath) return {schemaVersion:1,algorithm:'none',statement};
  const pem=await readFile(privateKeyPath,'utf8'); const key=createPrivateKey(pem); const payload=Buffer.from(JSON.stringify(statement)); const signature=sign('sha256',payload,key).toString('base64'); const publicPem=createPublicKey(key).export({type:'spki',format:'pem'}).toString(); const fp=createHash('sha256').update(publicPem).digest('hex');
  return {schemaVersion:1,algorithm:'sha256WithKey',statement,signature,publicKeyFingerprint:fp};
}
export async function verifyAttestation(attestation:SignedAttestation,publicKeyPath:string):Promise<boolean>{ if(attestation.algorithm==='none'||!attestation.signature) return false; const pem=await readFile(publicKeyPath,'utf8'); return verify('sha256',Buffer.from(JSON.stringify(attestation.statement)),createPublicKey(pem),Buffer.from(attestation.signature,'base64')); }
