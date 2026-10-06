import { readFile } from 'node:fs/promises';
import { resolve, relative, sep } from 'node:path';
import { SCHEMA_VERSION, type ScannerContext, type ScannerPlugin, type ScannerResult } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';
import { componentsFromCycloneDx, findingsFromGrype } from './adapters.js';

const base='.sentrycode/supply-chain';
async function readJson(root:string,name:string):Promise<unknown|undefined>{try{return JSON.parse(await readFile(resolve(root,base,name),'utf8'));}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return undefined;throw e;}}
function safePath(root:string,name:string){const p=resolve(root,base,name);const r=relative(resolve(root),p);if(r.split(sep).includes('..')||r.startsWith('..'))throw new Error('Supply-chain report escapes repository');return p;}
export class SupplyChainScanner implements ScannerPlugin {
 readonly id='supply-chain'; readonly version='0.1.0';
 async scan(context:ScannerContext):Promise<ScannerResult>{
  const started=performance.now();const at=context.now().toISOString();const syft=await readJson(context.repository.root,'syft.cdx.json');const grype=await readJson(context.repository.root,'grype.json');
  if(syft===undefined&&grype===undefined)return {scanner:this.id,findings:[],evidence:[],durationMs:Math.round(performance.now()-started),status:'skipped',error:'No operator-produced Syft/Grype reports available'};
  if(syft===undefined||grype===undefined)throw new Error('Syft and Grype reports are required together');
  safePath(context.repository.root,'syft.cdx.json');safePath(context.repository.root,'grype.json');
  const binding=await readJson(context.repository.root,'binding.json');
  if(!binding||typeof binding!=='object'||Array.isArray(binding))throw new Error('Supply-chain binding manifest is required');
  const b=binding as Record<string,unknown>;if(b.commitSha!==context.repository.commitSha||b.repository!==context.repository.repository||typeof b.inputDigest!=='string'||b.provider!=='syft-grype')throw new Error('Supply-chain report binding mismatch');
  const components=componentsFromCycloneDx(syft);const matches=findingsFromGrype(grype,at);const findings=matches.map(x=>x.finding);
  const id=stableId('evidence',`${context.repository.commitSha}|supply-chain|${at}`);
  return {scanner:this.id,findings,evidence:[{schemaVersion:SCHEMA_VERSION,id,type:'supply-chain.scan',scanner:this.id,repository:context.repository.repository,commitSha:context.repository.commitSha,branch:context.repository.branch,generatedAt:at,findingIds:findings.map(f=>f.id),metadata:{provider:'syft-grype',providerVersion:typeof b.providerVersion==='string'?b.providerVersion:'unknown',componentCount:components.length,matchCount:matches.length,inputDigest:b.inputDigest}}],durationMs:Math.round(performance.now()-started)};
 }
}
