import { SCHEMA_VERSION, type DependencyComponent, type Finding, type ScannerContext, type ScannerPlugin, type ScannerResult, type Severity } from '../../core/types.js';
import { discoverDependencies } from '../../dependencies/discover.js';
import { satisfiesSimpleRange } from '../../dependencies/versions.js';
import { cyclonedxSbom } from '../../sbom/generate.js';
import { loadVulnerabilityDatabase, vulnerabilitiesFor } from '../../vulnerabilities/database.js';
import { stableId } from '../../utils/hash.js';
import { discoverServices } from '../../monorepo/discover.js';
import { enrichDependencyMetadata } from '../../dependencies/metadata.js';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

function finding(args: { type: string; ruleId: string; title: string; description: string; severity: Severity; component: DependencyComponent; detectedAt: string; remediation?: string; metadata?: Record<string, string | number | boolean | null> }): Finding {
  const fingerprint = stableId('fp', `${args.ruleId}|${args.component.ecosystem}|${args.component.name}|${args.component.version}`);
  return {
    schemaVersion: SCHEMA_VERSION, id: stableId('finding', `${fingerprint}|${args.detectedAt}`), type: args.type, scanner: 'dependencies', ruleId: args.ruleId,
    title: args.title, description: args.description, severity: args.severity, fingerprint, detectedAt: args.detectedAt,
    ...(args.remediation ? { remediation: args.remediation } : {}),
    metadata: { ecosystem: args.component.ecosystem, package: args.component.name, version: args.component.version, purl: args.component.purl, direct: args.component.direct, ...args.metadata }
  };
}

function effectiveLicense(component: DependencyComponent, overrides: Record<string, string>): string | undefined {
  return overrides[component.name] ?? overrides[`${component.ecosystem}:${component.name}`] ?? component.license;
}

function registryHost(source:string):string|undefined { if(!/^https?:\/\//i.test(source))return undefined;try{return new URL(source).hostname.toLowerCase()}catch{return undefined} }
function hostMatches(host:string,item:string):boolean { const normalized=item.toLowerCase();return host===normalized||host.endsWith(`.${normalized}`); }
function registryAllowed(source: string, allowed: string[]): boolean { const host=registryHost(source); if (!allowed.length || !host) return true; return allowed.some((item) => hostMatches(host,item)); }
function registryDenied(source:string,denied:string[]):boolean {const host=registryHost(source);return Boolean(host&&denied.some(item=>hostMatches(host,item)));}

type HealthRecord={lastReleaseAt?:string;deprecated?:boolean};
async function loadHealth(root:string,path:string):Promise<Record<string,HealthRecord>>{try{const raw=JSON.parse(await readFile(resolve(root,path),'utf8')) as unknown;if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new Error('dependency health metadata must be an object');const obj=raw as Record<string,unknown>;const packages=(obj.packages&&typeof obj.packages==='object'&&!Array.isArray(obj.packages)?obj.packages:obj) as Record<string,unknown>;const out:Record<string,HealthRecord>={};for(const [key,value] of Object.entries(packages)){if(value&&typeof value==='object'&&!Array.isArray(value)){const v=value as Record<string,unknown>;out[key]={...(typeof v.lastReleaseAt==='string'?{lastReleaseAt:v.lastReleaseAt}:{}),...(typeof v.deprecated==='boolean'?{deprecated:v.deprecated}:{})};}}return out;}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return {};throw error;}}

export class DependencyScanner implements ScannerPlugin {
  readonly id = 'dependencies';
  readonly version = '0.2.0';

  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now();
    const detectedAt = context.now().toISOString();
    if (!context.config.dependencies.enabled) return { scanner: this.id, findings: [], evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped', error: 'scanner disabled by configuration' };
    let serviceRoot = '';
    const requestedService = context.execution?.service ?? context.config.policy.context.service;
    if (requestedService) {
      const services = await discoverServices(context.repository.root, context.config);
      const selected = services.find((item) => item.name === requestedService || item.root === requestedService);
      if (!selected) throw new Error(`Unknown service for dependency scan: ${requestedService}`);
      serviceRoot = selected.root;
    }
    const snapshot = await discoverDependencies(context.repository.root, detectedAt, serviceRoot);
    const enriched = await enrichDependencyMetadata(context.repository.root, snapshot.components, { serviceRoot, offline: context.config.offline.enabled });
    const components = enriched.filter((item) => context.config.dependencies.includeDev || !item.dev);
    const findings: Finding[] = [];
    const health=context.config.dependencies.maintenance.enabled ? await loadHealth(context.repository.root,context.config.dependencies.maintenance.metadataFile) : {};

    for (const component of components) {
      const packageKeys = [component.name, `${component.ecosystem}:${component.name}`];
      if (context.config.dependencies.deniedPackages.some((item) => packageKeys.includes(item))) {
        findings.push(finding({ type: 'dependency', ruleId: 'dependency.denied', title: 'Denied dependency', description: `${component.name} is denied by dependency policy.`, severity: 'high', component, detectedAt, remediation: 'Remove the dependency or change the governing dependency policy through an approved process.' }));
      }
      if (context.config.dependencies.allowedPackages.length && !context.config.dependencies.allowedPackages.some((item) => packageKeys.includes(item))) {
        findings.push(finding({ type: 'dependency', ruleId: 'dependency.not-allowed', title: 'Unapproved dependency', description: `${component.name} is not in the configured dependency allowlist.`, severity: 'high', component, detectedAt }));
      }
      const restriction = context.config.dependencies.versionRestrictions[component.name] ?? context.config.dependencies.versionRestrictions[`${component.ecosystem}:${component.name}`];
      if (restriction && !satisfiesSimpleRange(component.version, restriction)) {
        findings.push(finding({ type: 'dependency', ruleId: 'dependency.version-restricted', title: 'Dependency version violates policy', description: `${component.name}@${component.version} does not satisfy ${restriction}.`, severity: 'high', component, detectedAt, metadata: { requiredRange: restriction } }));
      }
      if (registryDenied(component.source, context.config.dependencies.deniedRegistries)) {
        findings.push(finding({ type: 'dependency', ruleId: 'dependency.registry-denied', title: 'Dependency from denied registry', description: `${component.name} resolves from a denied registry.`, severity: 'high', component, detectedAt, metadata: { source: component.source } }));
      } else if (!registryAllowed(component.source, context.config.dependencies.allowedRegistries)) {
        findings.push(finding({ type: 'dependency', ruleId: 'dependency.registry-unapproved', title: 'Dependency from unapproved registry', description: `${component.name} resolves from an unapproved registry.`, severity: 'high', component, detectedAt, metadata: { source: component.source } }));
      }
      if(context.config.dependencies.maintenance.enabled){
        const record=health[`${component.ecosystem}:${component.name}`]??health[component.name];
        if(!record&&context.config.dependencies.maintenance.requireMetadata)findings.push(finding({type:'dependency',ruleId:'dependency.maintenance-metadata-missing',title:'Dependency maintenance metadata unavailable',description:`No governed maintenance metadata is available for ${component.name}@${component.version}.`,severity:'high',component,detectedAt}));
        if(record?.deprecated&&context.config.dependencies.maintenance.denyDeprecated)findings.push(finding({type:'dependency',ruleId:'dependency.deprecated',title:'Deprecated dependency',description:`${component.name}@${component.version} is marked deprecated by governed maintenance metadata.`,severity:'high',component,detectedAt}));
        if(record?.lastReleaseAt){const released=Date.parse(record.lastReleaseAt);if(Number.isNaN(released)){findings.push(finding({type:'dependency',ruleId:'dependency.maintenance-metadata-invalid',title:'Invalid dependency maintenance metadata',description:`${component.name} has an invalid lastReleaseAt value.`,severity:'high',component,detectedAt}));}else{const age=(context.now().getTime()-released)/86400000;if(age>context.config.dependencies.maintenance.maxReleaseAgeDays)findings.push(finding({type:'dependency',ruleId:'dependency.stale',title:'Dependency exceeds maintenance age policy',description:`${component.name}@${component.version} has not had a governed release within ${context.config.dependencies.maintenance.maxReleaseAgeDays} days.`,severity:'high',component,detectedAt,metadata:{lastReleaseAt:record.lastReleaseAt,ageDays:Math.floor(age)}}));}}
      }

      if (context.config.licenses.enabled) {
        const license = effectiveLicense(component, context.config.licenses.overrides);
        if (!license) {
          if (context.config.licenses.unknown !== 'allow') findings.push(finding({ type: 'license', ruleId: 'license.unknown', title: 'Unknown dependency license', description: `No license information is available for ${component.name}@${component.version}.`, severity: context.config.licenses.unknown === 'fail' ? 'high' : 'medium', component, detectedAt }));
        } else if (context.config.licenses.denied.includes(license)) {
          findings.push(finding({ type: 'license', ruleId: 'license.denied', title: 'Denied dependency license', description: `${component.name}@${component.version} declares denied license ${license}.`, severity: 'high', component, detectedAt, metadata: { license } }));
        } else if (context.config.licenses.allowed.length && !context.config.licenses.allowed.includes(license)) {
          findings.push(finding({ type: 'license', ruleId: 'license.not-allowed', title: 'License not in allowlist', description: `${license} is not in the configured license allowlist.`, severity: 'high', component, detectedAt, metadata: { license } }));
        } else if (context.config.licenses.reviewRequired.includes(license)) {
          findings.push(finding({ type: 'license', ruleId: 'license.review-required', title: 'License requires review', description: `${component.name}@${component.version} uses ${license}, which requires review.`, severity: 'medium', component, detectedAt, metadata: { license } }));
        }
      }
    }

    let dbUpdatedAt: string | undefined;
    if (context.config.vulnerabilities.enabled) {
      const db = await loadVulnerabilityDatabase(context.repository.root, context.config.vulnerabilities.databaseFile);
      dbUpdatedAt = db.updatedAt;
      if (context.config.offline.enabled && !db.available) throw new Error(`Offline vulnerability database is required but unavailable: ${context.config.vulnerabilities.databaseFile}`);
      for (const component of components) {
        for (const advisory of vulnerabilitiesFor(component, db.advisories)) {
          const severity: Severity = advisory.knownExploited && context.config.vulnerabilities.failOnKnownExploited && !['high', 'critical'].includes(advisory.severity) ? 'high' : advisory.severity;
          findings.push(finding({ type: 'vulnerability', ruleId: advisory.id, title: advisory.title ?? `Known vulnerability ${advisory.id}`, description: `${component.name}@${component.version} matches affected range ${advisory.affected}.`, severity, component, detectedAt, remediation: advisory.fixedVersion ? `Upgrade to ${advisory.fixedVersion} or later after compatibility validation.` : 'Review the advisory and remediate or create a time-bounded approved waiver.', metadata: { advisoryId: advisory.id, affectedRange: advisory.affected, fixedVersion: advisory.fixedVersion ?? null, knownExploited: advisory.knownExploited ?? false, source: advisory.source ?? null, url: advisory.url ?? null } }));
        }
      }
    }

    const unique = [...new Map(findings.map((item) => [item.fingerprint, item])).values()];
    const baseMetadata = { scannerVersion: this.version, serviceRoot: serviceRoot || '.', componentCount: components.length, npmComponents: components.filter((item) => item.ecosystem === 'npm').length, pypiComponents: components.filter((item) => item.ecosystem === 'pypi').length, mavenComponents: components.filter((item) => item.ecosystem === 'maven').length, nugetComponents: components.filter((item) => item.ecosystem === 'nuget').length, conanComponents: components.filter((item) => item.ecosystem === 'conan').length, vcpkgComponents: components.filter((item) => item.ecosystem === 'vcpkg').length, cargoComponents: components.filter((item) => item.ecosystem === 'cargo').length, goComponents: components.filter((item) => item.ecosystem === 'go').length };
    const ids = (type: string) => unique.filter((item) => item.type === type).map((item) => item.id);
    const evidence = [
      { schemaVersion: SCHEMA_VERSION, id: stableId('evidence', `${context.repository.commitSha}|sbom|${detectedAt}`), type: 'sbom.generated', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch, generatedAt: detectedAt, findingIds: [], metadata: { ...baseMetadata, format: 'CycloneDX 1.5', componentCount: components.length, bomBytes: JSON.stringify(cyclonedxSbom(context.repository, components, detectedAt)).length } },
      { schemaVersion: SCHEMA_VERSION, id: stableId('evidence', `${context.repository.commitSha}|dependency|${detectedAt}`), type: 'dependency.check', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch, generatedAt: detectedAt, findingIds: ids('dependency'), metadata: { ...baseMetadata, findingCount: ids('dependency').length } },
      { schemaVersion: SCHEMA_VERSION, id: stableId('evidence', `${context.repository.commitSha}|license|${detectedAt}`), type: 'license.check', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch, generatedAt: detectedAt, findingIds: ids('license'), metadata: { ...baseMetadata, findingCount: ids('license').length } },
      { schemaVersion: SCHEMA_VERSION, id: stableId('evidence', `${context.repository.commitSha}|vuln|${detectedAt}`), type: 'vuln.scan', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch, generatedAt: detectedAt, findingIds: ids('vulnerability'), metadata: { ...baseMetadata, findingCount: ids('vulnerability').length, databaseUpdatedAt: dbUpdatedAt ?? null } }
    ];
    return { scanner: this.id, findings: unique, evidence, durationMs: Math.round(performance.now() - started) };
  }
}
