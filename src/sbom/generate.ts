import { randomUUID } from 'node:crypto';
import type { DependencyComponent, RepositoryContext } from '../core/types.js';

function componentType(component: DependencyComponent): string { return component.direct ? 'library' : 'library'; }

export function cyclonedxSbom(repository: RepositoryContext, components: DependencyComponent[], generatedAt: string): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: {
      timestamp: generatedAt,
      component: { type: 'application', name: repository.repository, ...(repository.commitSha ? { version: repository.commitSha } : {}) },
      properties: [
        { name: 'quilons:sentrycode:branch', value: repository.branch ?? 'unavailable' },
        { name: 'quilons:sentrycode:dirty', value: String(repository.isDirty) }
      ]
    },
    components: components.map((item) => ({
      type: componentType(item), name: item.name, version: item.version, purl: item.purl,
      scope: item.dev ? 'optional' : 'required',
      ...(item.license ? { licenses: [{ license: { id: item.license } }] } : {}),
      properties: [
        { name: 'quilons:sentrycode:ecosystem', value: item.ecosystem },
        { name: 'quilons:sentrycode:direct', value: String(item.direct) },
        { name: 'quilons:sentrycode:source', value: item.source }
      ]
    }))
  };
}

export function spdxSbom(repository: RepositoryContext, components: DependencyComponent[], generatedAt: string): Record<string, unknown> {
  const namespace = `https://quilons.ai/sentrycode/spdx/${encodeURIComponent(repository.repository)}/${repository.commitSha ?? randomUUID()}`;
  return {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `${repository.repository}-sbom`, documentNamespace: namespace,
    creationInfo: { created: generatedAt, creators: ['Tool: QUILONS SentryCode-0.2.0'] },
    packages: components.map((item, index) => ({
      SPDXID: `SPDXRef-Package-${index + 1}`, name: item.name, versionInfo: item.version, downloadLocation: item.source.startsWith('http') ? item.source : 'NOASSERTION',
      filesAnalyzed: false, licenseConcluded: item.license ?? 'NOASSERTION', licenseDeclared: item.license ?? 'NOASSERTION',
      externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: item.purl }]
    }))
  };
}
