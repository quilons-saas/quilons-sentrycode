import { randomUUID } from 'node:crypto';
import type { DependencyComponent, RepositoryContext } from '../core/types.js';

function componentType(_component: DependencyComponent): string { return 'library'; }
function spdxId(index:number):string{return `SPDXRef-Package-${index+1}`;}

export function cyclonedxSbom(repository: RepositoryContext, components: DependencyComponent[], generatedAt: string): Record<string, unknown> {
  const rootRef=`pkg:generic/${encodeURIComponent(repository.repository)}@${encodeURIComponent(repository.commitSha??'uncommitted')}`;
  const refs=new Set(components.map(c=>c.purl));
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: {
      timestamp: generatedAt,
      component: { type: 'application', name: repository.repository, 'bom-ref':rootRef, ...(repository.commitSha ? { version: repository.commitSha } : {}) },
      properties: [
        { name: 'quilons:sentrycode:branch', value: repository.branch ?? 'unavailable' },
        { name: 'quilons:sentrycode:dirty', value: String(repository.isDirty) }
      ]
    },
    components: components.map((item) => ({
      type: componentType(item), name: item.name, version: item.version, purl: item.purl, 'bom-ref':item.purl,
      scope: item.dev ? 'optional' : 'required',
      ...(item.hashes?.length ? { hashes:item.hashes.map(h=>({alg:h.algorithm,content:h.value})) } : {}),
      ...(item.license ? { licenses: [{ license: { id: item.license } }] } : {}),
      properties: [
        { name: 'quilons:sentrycode:ecosystem', value: item.ecosystem },
        { name: 'quilons:sentrycode:direct', value: String(item.direct) },
        { name: 'quilons:sentrycode:source', value: item.source },
        ...(item.replacedFrom?[{name:'quilons:sentrycode:replaced-from',value:item.replacedFrom}]:[])
      ]
    })),
    dependencies:[
      {ref:rootRef,dependsOn:components.filter(c=>c.direct).map(c=>c.purl)},
      ...components.map(c=>({ref:c.purl,dependsOn:(c.dependencies??[]).filter(d=>refs.has(d))}))
    ]
  };
}

export function spdxSbom(repository: RepositoryContext, components: DependencyComponent[], generatedAt: string): Record<string, unknown> {
  const namespace = `https://quilons.ai/sentrycode/spdx/${encodeURIComponent(repository.repository)}/${repository.commitSha ?? randomUUID()}`;
  const idByPurl=new Map(components.map((c,i)=>[c.purl,spdxId(i)]));
  const rootId='SPDXRef-RootPackage';
  const relationships:Array<Record<string,string>>=[{spdxElementId:'SPDXRef-DOCUMENT',relationshipType:'DESCRIBES',relatedSpdxElement:rootId}];
  for(const [i,item] of components.entries()){
    const id=spdxId(i); if(item.direct)relationships.push({spdxElementId:rootId,relationshipType:'DEPENDS_ON',relatedSpdxElement:id});
    for(const dep of item.dependencies??[]){const depId=idByPurl.get(dep);if(depId)relationships.push({spdxElementId:id,relationshipType:'DEPENDS_ON',relatedSpdxElement:depId});}
  }
  return {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `${repository.repository}-sbom`, documentNamespace: namespace,
    creationInfo: { created: generatedAt, creators: ['Tool: QUILONS SentryCode-0.1.0'] },
    packages: [
      {SPDXID:rootId,name:repository.repository,versionInfo:repository.commitSha??'uncommitted',downloadLocation:'NOASSERTION',filesAnalyzed:false,licenseConcluded:'NOASSERTION',licenseDeclared:'NOASSERTION'},
      ...components.map((item, index) => ({
        SPDXID: spdxId(index), name: item.name, versionInfo: item.version, downloadLocation: item.source.startsWith('http') ? item.source : 'NOASSERTION',
        filesAnalyzed: false, licenseConcluded: item.license ?? 'NOASSERTION', licenseDeclared: item.license ?? 'NOASSERTION',
        ...(item.hashes?.length?{checksums:item.hashes.map(h=>({algorithm:h.algorithm.replace('-',''),checksumValue:h.value}))}:{}),
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: item.purl }]
      }))
    ],
    relationships
  };
}
