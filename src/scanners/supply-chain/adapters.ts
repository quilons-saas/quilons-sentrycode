import { SCHEMA_VERSION, type DependencyComponent, type Finding, type Severity } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';

const severities = new Set<Severity>(['info','low','medium','high','critical']);
function severity(value: unknown): Severity { const v=String(value??'').toLowerCase(); return severities.has(v as Severity)?v as Severity:'medium'; }
function ecosystemFromPurl(purl:string): DependencyComponent['ecosystem'] {
 const type=purl.match(/^pkg:([^/]+)/)?.[1];
 const map:Record<string,DependencyComponent['ecosystem']>={npm:'npm',pypi:'pypi',maven:'maven',nuget:'nuget',cargo:'cargo',golang:'go',conan:'conan',deb:'vcpkg'};
 const e=map[type??'']; if(!e)throw new Error(`Unsupported SBOM ecosystem: ${type??'unknown'}`); return e;
}
function requiredString(v:unknown,name:string):string {if(typeof v!=='string'||!v.trim()||v.includes('\\0'))throw new Error(`Invalid ${name}`);return v;}
export function componentsFromCycloneDx(raw:unknown):DependencyComponent[] {
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new Error('CycloneDX document must be an object'); const d=raw as Record<string,unknown>;
 if(d.bomFormat!=='CycloneDX'||d.specVersion!=='1.5'||!Array.isArray(d.components))throw new Error('CycloneDX 1.5 inventory required');
 return d.components.map((x:unknown)=>{if(!x||typeof x!=='object'||Array.isArray(x))throw new Error('Malformed SBOM component');const c=x as Record<string,unknown>;const purl=requiredString(c.purl,'component purl');const name=requiredString(c.name,'component name');const version=requiredString(c.version,'component version');if(!/^pkg:[^/]+\/[^@]+@[^?]+/.test(purl))throw new Error('Invalid component purl');return {ecosystem:ecosystemFromPurl(purl),name,version,direct:false,dev:false,source:'syft',purl,...(typeof c.license==='string'?{license:c.license}:{})};});
}
export interface GrypeFinding { finding: Finding; vulnerabilityId:string; componentPurl:string; fixedVersions:string[] }
export function findingsFromGrype(raw:unknown, detectedAt:string):GrypeFinding[] {
 if(!raw||typeof raw!=="object"||Array.isArray(raw)) throw new Error("Grype document must be an object");
 const d=raw as Record<string,unknown>; if(!Array.isArray(d.matches)) throw new Error("Grype matches required");
 return d.matches.map((x:unknown,i)=>{
  if(!x||typeof x!=="object"||Array.isArray(x)) throw new Error("Malformed Grype match");
  const m=x as Record<string,unknown>; const vuln=m.vulnerability as Record<string,unknown>|undefined; const art=m.artifact as Record<string,unknown>|undefined;
  const id=requiredString(vuln?.id,`vulnerability id ${i}`); const purl=requiredString(art?.purl,`artifact purl ${i}`); const pkg=requiredString(art?.name,`artifact name ${i}`); const version=requiredString(art?.version,`artifact version ${i}`);
  const fp=stableId("fp",`grype|${id}|${purl}`); const fix=vuln?.fix as Record<string,unknown>|undefined; const fixedVersions=Array.isArray(fix?.versions)?fix.versions.filter((v):v is string=>typeof v==='string'):[];
  const cvss=Array.isArray(vuln?.cvss)?vuln.cvss[0] as Record<string,unknown>|undefined:undefined; const level=typeof vuln?.severity==='string'?vuln.severity:cvss?.severity;
  const finding:Finding={schemaVersion:SCHEMA_VERSION,id:stableId("finding",`${fp}|${detectedAt}`),type:"vulnerability",scanner:"grype",ruleId:id,title:`${id}: ${pkg}@${version}`,description:typeof vuln?.description==='string'?vuln.description:`${pkg}@${version} is affected by ${id}.`,severity:severity(level),fingerprint:fp,detectedAt,remediation:fixedVersions.length?`Upgrade to ${fixedVersions.join(", ")} after compatibility validation.`:"Review the advisory and remediate or create a governed waiver.",metadata:{package:pkg,version,purl,fixes:fixedVersions.join(","),source:"grype"}};
  return {vulnerabilityId:id,componentPurl:purl,fixedVersions,finding};
 });
}
