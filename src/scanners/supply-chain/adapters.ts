import { SCHEMA_VERSION, type DependencyComponent, type Finding, type Severity } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';

const severities = new Set<Severity>(['info', 'low', 'medium', 'high', 'critical']);
const severityRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function severity(value: unknown): Severity {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (severities.has(normalized as Severity)) return normalized as Severity;
  if (normalized === 'negligible' || normalized === 'unknown' || !normalized) return 'info';
  return 'info';
}

function ecosystemFromPurl(purl: string): DependencyComponent['ecosystem'] {
  const type = purl.match(/^pkg:([^/]+)/)?.[1]?.toLowerCase();
  const map: Record<string, DependencyComponent['ecosystem']> = {
    npm: 'npm', pypi: 'pypi', maven: 'maven', nuget: 'nuget', cargo: 'cargo', golang: 'go', conan: 'conan', vcpkg: 'vcpkg', apk: 'apk', deb: 'deb', rpm: 'rpm'
  };
  const ecosystem = map[type ?? ''];
  if (!ecosystem) throw new Error(`Unsupported SBOM ecosystem: ${type ?? 'unknown'}`);
  return ecosystem;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value.trim() || value.includes('\0')) throw new Error(`Invalid ${name}`);
  return value.trim();
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function componentLicense(component: Record<string, unknown>): string | undefined {
  if (typeof component.license === 'string' && component.license.trim()) return component.license.trim();
  const licenses = Array.isArray(component.licenses) ? component.licenses : [];
  const values: string[] = [];
  for (const entry of licenses) {
    const object = asObject(entry); if (!object) continue;
    if (typeof object.expression === 'string' && object.expression.trim()) values.push(object.expression.trim());
    const license = asObject(object.license);
    if (license && typeof license.id === 'string' && license.id.trim()) values.push(license.id.trim());
    else if (license && typeof license.name === 'string' && license.name.trim()) values.push(license.name.trim());
  }
  return values.length ? [...new Set(values)].join(' AND ') : undefined;
}

export interface UnresolvedInventoryComponent {
  name: string;
  version?: string;
  purl?: string;
  reason: 'missing-purl' | 'missing-version' | 'unsupported-ecosystem';
}

export interface ParsedInventory {
  components: DependencyComponent[];
  unresolved: UnresolvedInventoryComponent[];
  relationshipCoverage: {
    direct: number;
    transitive: number;
    os: number;
    unknown: number;
    graphAvailable: boolean;
  };
}

function dependencyGraph(document: Record<string, unknown>): { rootRef?: string; directRefs: Set<string>; reachableRefs: Set<string>; graphAvailable: boolean } {
  const metadata = asObject(document.metadata);
  const rootRef = asObject(metadata?.component)?.['bom-ref'];
  const edges = new Map<string, string[]>();
  if (Array.isArray(document.dependencies)) {
    for (const dependency of document.dependencies) {
      const object = asObject(dependency);
      if (!object || typeof object.ref !== 'string' || !Array.isArray(object.dependsOn)) continue;
      edges.set(object.ref, object.dependsOn.filter((ref): ref is string => typeof ref === 'string' && Boolean(ref)));
    }
  }
  if (typeof rootRef !== 'string' || !edges.has(rootRef)) return { directRefs: new Set(), reachableRefs: new Set(), graphAvailable: false };
  const directRefs = new Set(edges.get(rootRef) ?? []);
  const reachableRefs = new Set<string>();
  const pending = [...directRefs];
  while (pending.length) {
    const ref = pending.pop()!;
    if (reachableRefs.has(ref)) continue;
    reachableRefs.add(ref);
    for (const child of edges.get(ref) ?? []) if (!reachableRefs.has(child)) pending.push(child);
  }
  return { rootRef, directRefs, reachableRefs, graphAvailable: true };
}

function relationshipFor(ecosystem: DependencyComponent['ecosystem'], bomRef: string, graph: ReturnType<typeof dependencyGraph>): NonNullable<DependencyComponent['relationship']> {
  if (ecosystem === 'apk' || ecosystem === 'deb' || ecosystem === 'rpm') return 'os';
  if (!graph.graphAvailable) return 'unknown';
  if (graph.directRefs.has(bomRef)) return 'direct';
  if (graph.reachableRefs.has(bomRef)) return 'transitive';
  return 'unknown';
}

function relationshipRank(value: DependencyComponent['relationship']): number {
  return value === 'direct' ? 4 : value === 'os' ? 3 : value === 'transitive' ? 2 : 1;
}

export function inventoryFromCycloneDx(raw: unknown): ParsedInventory {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('CycloneDX document must be an object');
  const document = raw as Record<string, unknown>;
  if (document.bomFormat !== 'CycloneDX' || document.specVersion !== '1.5' || !Array.isArray(document.components)) throw new Error('CycloneDX 1.5 inventory required');

  const graph = dependencyGraph(document);
  const byPurl = new Map<string, DependencyComponent>();
  const unresolvedByKey = new Map<string, UnresolvedInventoryComponent>();
  for (const item of document.components) {
    const component = asObject(item);
    if (!component) throw new Error('Malformed SBOM component');
    const name = requiredString(component.name, 'component name');
    const version = typeof component.version === 'string' && component.version.trim() ? component.version.trim() : undefined;
    const purl = typeof component.purl === 'string' && component.purl.trim() ? component.purl.trim() : undefined;
    if (!purl) {
      const unresolved = { name, ...(version ? { version } : {}), reason: 'missing-purl' as const };
      unresolvedByKey.set(`${name}|${version ?? ''}|missing-purl`, unresolved);
      continue;
    }
    if (!version) {
      const unresolved = { name, purl, reason: 'missing-version' as const };
      unresolvedByKey.set(`${name}|${purl}|missing-version`, unresolved);
      continue;
    }
    if (!/^pkg:[^/]+\/.+@[^?]+/.test(purl)) throw new Error('Invalid component purl');
    let ecosystem: DependencyComponent['ecosystem'];
    try { ecosystem = ecosystemFromPurl(purl); }
    catch {
      const unresolved = { name, version, purl, reason: 'unsupported-ecosystem' as const };
      unresolvedByKey.set(`${purl}|unsupported-ecosystem`, unresolved);
      continue;
    }
    const bomRef = typeof component['bom-ref'] === 'string' && component['bom-ref'] ? component['bom-ref'] : purl;
    const relationship = relationshipFor(ecosystem, bomRef, graph);
    const license = componentLicense(component);
    const inventoryScope = typeof component.scope === 'string' && component.scope.trim() ? component.scope.trim() : undefined;
    const normalized: DependencyComponent = {
      ecosystem, name, version, direct: relationship === 'direct', relationship, dev: false, source: 'syft', purl,
      ...(inventoryScope ? { inventoryScope } : {}),
      ...(license ? { license } : {})
    };
    const existing = byPurl.get(purl);
    if (!existing) byPurl.set(purl, normalized);
    else {
      const existingRelationship = existing.relationship ?? 'unknown';
      const normalizedRelationship = normalized.relationship ?? 'unknown';
      const preferred: NonNullable<DependencyComponent['relationship']> =
        relationshipRank(normalizedRelationship) > relationshipRank(existingRelationship) ? normalizedRelationship : existingRelationship;
      byPurl.set(purl, {
        ...existing,
        relationship: preferred,
        direct: preferred === 'direct',
        ...(existing.license ? {} : normalized.license ? { license: normalized.license } : {}),
        ...(existing.inventoryScope ? {} : normalized.inventoryScope ? { inventoryScope: normalized.inventoryScope } : {})
      });
    }
  }
  const components = [...byPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl));
  const relationshipCoverage = {
    direct: components.filter((component) => component.relationship === 'direct').length,
    transitive: components.filter((component) => component.relationship === 'transitive').length,
    os: components.filter((component) => component.relationship === 'os').length,
    unknown: components.filter((component) => component.relationship === 'unknown').length,
    graphAvailable: graph.graphAvailable
  };
  return { components, unresolved: [...unresolvedByKey.values()], relationshipCoverage };
}

/** Strict compatibility helper retained for callers that require every component to be supported. */
export function componentsFromCycloneDx(raw: unknown): DependencyComponent[] {
  const parsed = inventoryFromCycloneDx(raw);
  if (parsed.unresolved.length) throw new Error(`Unsupported or unresolved SBOM component: ${parsed.unresolved[0]!.name}`);
  const legacySupported = new Set<DependencyComponent['ecosystem']>(['npm', 'pypi', 'maven', 'nuget', 'cargo', 'go', 'conan', 'vcpkg']);
  const unsupported = parsed.components.find((component) => !legacySupported.has(component.ecosystem));
  if (unsupported) throw new Error(`Unsupported SBOM ecosystem: ${unsupported.ecosystem}`);
  return parsed.components;
}

function boundedText(value: unknown, max = 2048): string | undefined {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  return value.trim().slice(0, max);
}

function matchRationale(match: Record<string, unknown>): string | undefined {
  if (!Array.isArray(match.matchDetails)) return undefined;
  const details = match.matchDetails.map(asObject).filter((item): item is Record<string, unknown> => Boolean(item));
  const normalized = details.slice(0, 8).map((detail) => {
    const matcher = boundedText(detail.matcher, 128) ?? 'unknown';
    const type = boundedText(detail.type, 128) ?? 'unknown';
    const searchedBy = asObject(detail.searchedBy);
    const found = asObject(detail.found);
    return {
      matcher,
      type,
      searchedBy: searchedBy ? Object.fromEntries(Object.entries(searchedBy).filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value)).slice(0, 8)) : undefined,
      found: found ? Object.fromEntries(Object.entries(found).filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value)).slice(0, 8)) : undefined
    };
  });
  return normalized.length ? JSON.stringify(normalized).slice(0, 4096) : undefined;
}

function csvValues(value: unknown): string[] {
  if (typeof value !== 'string' || !value) return [];
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function mergeCsv(a: unknown, b: unknown): string {
  return [...new Set([...csvValues(a), ...csvValues(b)])].sort().join(',');
}

export interface GrypeFinding { finding: Finding; vulnerabilityId: string; componentPurl: string; fixedVersions: string[] }

export function findingsFromGrype(raw: unknown, detectedAt: string): GrypeFinding[] {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Grype document must be an object');
  const document = raw as Record<string, unknown>;
  if (!Array.isArray(document.matches)) throw new Error('Grype matches required');
  const normalized = new Map<string, GrypeFinding>();

  for (const [index, item] of document.matches.entries()) {
    const match = asObject(item); if (!match) throw new Error('Malformed Grype match');
    const vulnerability = asObject(match.vulnerability); const artifact = asObject(match.artifact);
    const id = requiredString(vulnerability?.id, `vulnerability id ${index}`);
    const purl = requiredString(artifact?.purl, `artifact purl ${index}`);
    const pkg = requiredString(artifact?.name, `artifact name ${index}`);
    const version = requiredString(artifact?.version, `artifact version ${index}`);
    const fingerprint = stableId('fp', `grype|${id}|${purl}`);
    const fix = asObject(vulnerability?.fix);
    const fixedVersions = Array.isArray(fix?.versions) ? fix.versions.filter((value): value is string => typeof value === 'string' && Boolean(value.trim())).map((value) => value.trim()) : [];
    const cvssEntries = Array.isArray(vulnerability?.cvss) ? vulnerability.cvss.map(asObject).filter((value): value is Record<string, unknown> => Boolean(value)) : [];
    const cvss = cvssEntries.find((value) => typeof value.metrics === 'object') ?? cvssEntries[0];
    const metrics = asObject(cvss?.metrics);
    const nativeSeverity = typeof vulnerability?.severity === 'string' ? vulnerability.severity : typeof cvss?.severity === 'string' ? cvss.severity : 'unknown';
    const aliases = Array.isArray(match.relatedVulnerabilities)
      ? match.relatedVulnerabilities.map(asObject).flatMap((value) => value && typeof value.id === 'string' ? [value.id] : [])
      : [];
    const locations = Array.isArray(artifact?.locations)
      ? artifact.locations.map(asObject).flatMap((value) => value && typeof value.path === 'string' ? [value.path] : [])
      : [];
    const metadata: Record<string, string | number | boolean | null> = {
      package: pkg, version, purl, fixes: [...new Set(fixedVersions)].sort().join(','), source: 'grype', nativeSeverity, severityKnown: severities.has(nativeSeverity.trim().toLowerCase() as Severity), severityMapping: 'grype-v1',
      aliases: [...new Set(aliases)].sort().join(','), locations: [...new Set(locations)].sort().join(','), fixState: typeof fix?.state === 'string' ? fix.state : 'unknown'
    };
    const baseScore = Number(metrics?.baseScore);
    if (Number.isFinite(baseScore)) metadata.cvssBaseScore = baseScore;
    if (typeof cvss?.vector === 'string') metadata.cvssVector = cvss.vector;
    if (typeof vulnerability?.dataSource === 'string') metadata.dataSource = vulnerability.dataSource;
    if (typeof vulnerability?.namespace === 'string') metadata.namespace = vulnerability.namespace;
    if (typeof artifact?.type === 'string') metadata.packageType = artifact.type;
    const rationale = matchRationale(match);
    if (rationale) metadata.matchRationale = rationale;
    const finding: Finding = {
      schemaVersion: SCHEMA_VERSION, id: stableId('finding', `${fingerprint}|${detectedAt}`), type: 'vulnerability', scanner: 'grype', ruleId: id,
      title: `${id}: ${pkg}@${version}`,
      description: typeof vulnerability?.description === 'string' ? vulnerability.description : `${pkg}@${version} is affected by ${id}.`,
      severity: severity(nativeSeverity), fingerprint, detectedAt,
      remediation: fixedVersions.length ? `Upgrade to ${[...new Set(fixedVersions)].sort().join(', ')} after compatibility validation.` : 'Review the advisory and remediate or create a governed waiver.',
      metadata
    };
    const key = `${id}\0${purl}\0${version}`;
    const previous = normalized.get(key);
    if (!previous) {
      normalized.set(key, { vulnerabilityId: id, componentPurl: purl, fixedVersions: [...new Set(fixedVersions)].sort(), finding });
      continue;
    }
    const previousMetadata = previous.finding.metadata ?? {};
    const mergedFixed = [...new Set([...previous.fixedVersions, ...fixedVersions])].sort();
    const nextSeverity = severityRank[finding.severity] > severityRank[previous.finding.severity] ? finding.severity : previous.finding.severity;
    previous.fixedVersions = mergedFixed;
    previous.finding = {
      ...previous.finding,
      severity: nextSeverity,
      ...(mergedFixed.length
        ? { remediation: `Upgrade to ${mergedFixed.join(', ')} after compatibility validation.` }
        : previous.finding.remediation ? { remediation: previous.finding.remediation } : {}),
      metadata: {
        ...previousMetadata,
        ...finding.metadata,
        aliases: mergeCsv(previousMetadata.aliases, finding.metadata?.aliases),
        locations: mergeCsv(previousMetadata.locations, finding.metadata?.locations),
        fixes: mergedFixed.join(','),
        matchRationale: [boundedText(previousMetadata.matchRationale, 4096), boundedText(finding.metadata?.matchRationale, 4096)].filter(Boolean).join('\n').slice(0, 4096)
      }
    };
  }
  return [...normalized.values()].sort((a, b) => `${a.vulnerabilityId}|${a.componentPurl}`.localeCompare(`${b.vulnerabilityId}|${b.componentPurl}`));
}
