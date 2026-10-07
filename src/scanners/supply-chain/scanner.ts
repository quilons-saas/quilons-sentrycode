import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve, relative, sep } from 'node:path';
import { SCHEMA_VERSION, type DependencyComponent, type ScannerContext, type ScannerPlugin, type ScannerResult } from '../../core/types.js';
import { RunnerClient } from '../../execution/runner-client.js';
import type { RunnerJobResponseV1 } from '../../execution/contracts.js';
import { immutableImageDigest, sha256 } from '../../execution/contracts.js';
import { stableId } from '../../utils/hash.js';
import { discoverDependencies } from '../../dependencies/discover.js';
import { inventoryFromCycloneDx, findingsFromGrype, type ParsedInventory, type UnresolvedInventoryComponent } from './adapters.js';

const base = '.sentrycode/supply-chain';

function unresolvedFinding(item: UnresolvedInventoryComponent, detectedAt: string) {
  const subject = `${item.name}|${item.version ?? 'unknown'}|${item.purl ?? 'no-purl'}|${item.reason}`;
  const fingerprint = stableId('fp', `syft-unresolved|${subject}`);
  return {
    schemaVersion: SCHEMA_VERSION,
    id: stableId('finding', `${fingerprint}|${detectedAt}`),
    type: 'coverage', scanner: 'supply-chain', ruleId: 'dependency.inventory-unresolved',
    title: `Dependency inventory coverage incomplete: ${item.name}`,
    description: `Syft reported ${item.name}${item.version ? `@${item.version}` : ''}, but SentryCode could not normalize it (${item.reason}).`,
    severity: 'info' as const, fingerprint, detectedAt,
    remediation: 'Review the package identity and supported ecosystem mapping. Unresolved inventory remains incomplete coverage and cannot be treated as a clean dependency result.',
    metadata: { package: item.name, version: item.version ?? null, purl: item.purl ?? null, reason: item.reason, source: 'syft', coverageState: 'incomplete' }
  };
}

async function readJson(root: string, name: string): Promise<unknown | undefined> {
  try { return JSON.parse(await readFile(resolve(root, base, name), 'utf8')) as unknown; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
}
function safePath(root: string, name: string): string {
  const path = resolve(root, base, name); const rel = relative(resolve(root), path);
  if (rel.split(sep).includes('..') || rel.startsWith('..')) throw new Error('Supply-chain report escapes repository');
  return path;
}
function artifactJson(response: RunnerJobResponseV1, name: string): { raw: unknown; sha256: string } {
  const matches = response.artifacts.filter((item) => item.name === name);
  if (matches.length !== 1) throw new Error(`Runner must produce exactly one required artifact: ${name}`);
  const artifact = matches[0]!;
  const bytes = Buffer.from(artifact.contentBase64, 'base64');
  if (bytes.length !== artifact.bytes || sha256(bytes) !== artifact.sha256) throw new Error(`Runner artifact integrity failure: ${name}`);
  if (!bytes.length) throw new Error(`Runner produced empty artifact: ${name}`);
  try { return { raw: JSON.parse(bytes.toString('utf8')) as unknown, sha256: artifact.sha256 }; }
  catch { throw new Error(`Runner produced invalid JSON artifact: ${name}`); }
}

function assertManagedResponse(response: RunnerJobResponseV1, now: Date): void {
  if (!response.profileVersion?.trim()) throw new Error('Supply-chain runner did not report the exact profile version');
  if (!/^[a-f0-9]{64}$/i.test(response.profileDigest)) throw new Error('Supply-chain runner did not report a valid profile digest');
  if (!response.rulesIdentity.trim()) throw new Error('Supply-chain runner did not report a rules/intelligence identity');
  const step = (id: string) => {
    const matches = response.steps.filter((item) => item.stepId === id);
    if (matches.length !== 1) throw new Error(`Supply-chain runner must report exactly one ${id} step`);
    return matches[0]!;
  };
  const syft = step('syft');
  const grype = step('grype');
  for (const item of [syft, grype]) {
    const digest = immutableImageDigest(item.imageRef);
    if (!digest || digest !== item.imageDigest.toLowerCase()) throw new Error(`Supply-chain ${item.stepId} image identity is not immutable/bound`);
    // Qualified profiles do not use finding-threshold exits; findings are carried in structured JSON.
    // Therefore non-zero means execution failure, never "findings found".
    if (item.outcome !== 'completed' || item.exitCode !== 0) throw new Error(`Supply-chain ${item.stepId} execution did not complete with exit 0`);
  }
  const intelligence = response.intelligence;
  if (!intelligence || !/^grype(?:$|-|_)/i.test(intelligence.provider)) throw new Error('Supply-chain runner did not report governed Grype vulnerability intelligence');
  if (!/^[a-f0-9]{64}$/i.test(intelligence.sha256)) throw new Error('Supply-chain intelligence digest is invalid');
  const builtAt = Date.parse(intelligence.builtAt);
  const importedAt = Date.parse(intelligence.importedAt);
  const nowMs = now.getTime();
  if (!Number.isFinite(builtAt) || !Number.isFinite(importedAt)) throw new Error('Supply-chain intelligence timestamps are invalid');
  if (importedAt < builtAt) throw new Error('Supply-chain intelligence import time predates build time');
  if (builtAt > nowMs + 5 * 60_000 || importedAt > nowMs + 5 * 60_000) throw new Error('Supply-chain intelligence timestamp is in the future');
  const ageHours = (nowMs - builtAt) / 3_600_000;
  if (!Number.isFinite(intelligence.maxAgeHours) || intelligence.maxAgeHours <= 0 || ageHours > intelligence.maxAgeHours) {
    throw new Error(`Supply-chain intelligence is stale or has an invalid freshness policy: ${ageHours.toFixed(1)}h`);
  }
}

async function reconcileRelationships(inventory: ParsedInventory, context: ScannerContext, generatedAt: string): Promise<ParsedInventory> {
  if (inventory.relationshipCoverage.unknown === 0) return inventory;
  const native = await discoverDependencies(context.repository.root, generatedAt);
  const byPurl = new Map(native.components.map((component) => [component.purl, component]));
  const byIdentity = new Map(native.components.map((component) => [`${component.ecosystem}\0${component.name.toLowerCase()}\0${component.version}`, component]));
  const components: DependencyComponent[] = inventory.components.map((component) => {
    if (component.relationship !== 'unknown') return component;
    const matched = byPurl.get(component.purl) ?? byIdentity.get(`${component.ecosystem}\0${component.name.toLowerCase()}\0${component.version}`);
    if (!matched) return component;
    return { ...component, relationship: matched.direct ? 'direct' : 'transitive', direct: matched.direct };
  });
  return {
    ...inventory,
    components,
    relationshipCoverage: {
      direct: components.filter((component) => component.relationship === 'direct').length,
      transitive: components.filter((component) => component.relationship === 'transitive').length,
      os: components.filter((component) => component.relationship === 'os').length,
      unknown: components.filter((component) => component.relationship === 'unknown').length,
      graphAvailable: inventory.relationshipCoverage.graphAvailable
    }
  };
}

export interface SupplyChainRunner {
  runRepositoryProfile(args: { runId: string; profileId: string; repositoryRoot: string; config: ScannerContext['config']; signal?: AbortSignal }): Promise<RunnerJobResponseV1>;
}

export class SupplyChainScanner implements ScannerPlugin {
  readonly id = 'supply-chain';
  readonly version = '0.4.0';
  constructor(private readonly injectedRunner?: SupplyChainRunner) {}

  private runner(context: ScannerContext): { client: SupplyChainRunner; profileId: string } | undefined {
    const config = context.config.execution?.runner;
    if (!config?.enabled) return undefined;
    const profileId = config.profiles[this.id];
    if (!profileId) throw new Error(`No runner profile configured for ${this.id}`);
    if (this.injectedRunner) return { client: this.injectedRunner, profileId };
    const token = process.env[config.tokenEnv];
    if (!token) throw new Error(`Runner credential is unavailable: ${config.tokenEnv}`);
    if (!config.tenant || !config.project) throw new Error('Runner tenant/project scope is not configured');
    return { client: new RunnerClient({ endpoint: config.endpoint, token, tenant: config.tenant, project: config.project, timeoutMs: config.timeoutMs }), profileId };
  }

  private async runManaged(context: ScannerContext, started: number, detectedAt: string, runner: { client: SupplyChainRunner; profileId: string }): Promise<ScannerResult> {
    const response = await runner.client.runRepositoryProfile({ runId: `supply-${randomUUID()}`, profileId: runner.profileId, repositoryRoot: context.repository.root, config: context.config, ...(context.signal ? { signal: context.signal } : {}) });
    if (response.outcome !== 'completed') throw new Error(`Supply-chain execution failed: ${response.errorCode ?? response.outcome}`);
    if (!response.cleanupConfirmed) throw new Error('Supply-chain execution cleanup was not confirmed');
    if (!this.injectedRunner) assertManagedResponse(response, context.now());
    const syft = artifactJson(response, 'syft.cdx.json');
    const grype = artifactJson(response, 'grype.json');
    const inventory = await reconcileRelationships(inventoryFromCycloneDx(syft.raw), context, detectedAt);
    const matches = findingsFromGrype(grype.raw, detectedAt);
    const findings = [...matches.map((item) => item.finding), ...inventory.unresolved.map((item) => unresolvedFinding(item, detectedAt))];
    const stepImages = response.steps.map((step) => `${step.stepId}:${step.imageRef}`).join(';');
    const incompleteReasons: string[] = [];
    if (inventory.unresolved.length) incompleteReasons.push(`${inventory.unresolved.length} unresolved component(s)`);
    if (inventory.relationshipCoverage.unknown) incompleteReasons.push(`${inventory.relationshipCoverage.unknown} component relationship(s) unresolved`);
    const evidence = [{
      schemaVersion: SCHEMA_VERSION,
      id: stableId('evidence', `${context.repository.commitSha}|supply-chain|${response.inputDigest}|${response.profileDigest}|${response.intelligence?.sha256 ?? response.rulesIdentity}`),
      type: 'supply-chain.scan', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch,
      generatedAt: detectedAt, findingIds: findings.map((finding) => finding.id),
      metadata: {
        provider: 'syft-grype', providerVersion: response.profileVersion ?? response.profileDigest,
        componentCount: inventory.components.length,
        directComponentCount: inventory.relationshipCoverage.direct,
        transitiveComponentCount: inventory.relationshipCoverage.transitive,
        osComponentCount: inventory.relationshipCoverage.os,
        unknownRelationshipCount: inventory.relationshipCoverage.unknown,
        dependencyGraphAvailable: inventory.relationshipCoverage.graphAvailable,
        ecosystems: [...new Set(inventory.components.map((component) => component.ecosystem))].sort().join(','),
        unresolvedComponentCount: inventory.unresolved.length, matchCount: matches.length,
        coverageComplete: incompleteReasons.length === 0,
        coverageLimitations: incompleteReasons.join('; '),
        inputDigest: response.inputDigest, profileId: response.profileId, profileVersion: response.profileVersion ?? 'unknown', profileDigest: response.profileDigest, rulesIdentity: response.rulesIdentity,
        syftReportSha256: syft.sha256, grypeReportSha256: grype.sha256, imageIdentities: stepImages, cleanupConfirmed: response.cleanupConfirmed,
        intelligenceProvider: response.intelligence?.provider ?? 'unavailable-in-injected-runner', intelligenceId: response.intelligence?.id ?? response.rulesIdentity, intelligenceSchema: response.intelligence?.schema ?? 'unknown',
        intelligenceBuiltAt: response.intelligence?.builtAt ?? null, intelligenceImportedAt: response.intelligence?.importedAt ?? null, intelligenceSha256: response.intelligence?.sha256 ?? null,
        intelligenceMaxAgeHours: response.intelligence?.maxAgeHours ?? null,
        intelligenceSources: response.intelligence?.sources.join(',') ?? ''
      }
    }];
    return {
      scanner: this.id,
      findings,
      evidence,
      durationMs: Math.round(performance.now() - started),
      ...(incompleteReasons.length ? { status: 'failed' as const, error: `Dependency inventory coverage incomplete: ${incompleteReasons.join('; ')}` } : {})
    };
  }

  private async runImported(context: ScannerContext, started: number, detectedAt: string): Promise<ScannerResult> {
    const syft = await readJson(context.repository.root, 'syft.cdx.json');
    const grype = await readJson(context.repository.root, 'grype.json');
    if (syft === undefined && grype === undefined) return { scanner: this.id, findings: [], evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped', error: 'Managed supply-chain runner is disabled and no operator-produced Syft/Grype reports are available' };
    if (syft === undefined || grype === undefined) throw new Error('Syft and Grype reports are required together');
    safePath(context.repository.root, 'syft.cdx.json'); safePath(context.repository.root, 'grype.json');
    const binding = await readJson(context.repository.root, 'binding.json');
    if (!binding || typeof binding !== 'object' || Array.isArray(binding)) throw new Error('Supply-chain binding manifest is required');
    const b = binding as Record<string, unknown>;
    if (b.commitSha !== context.repository.commitSha || b.repository !== context.repository.repository || typeof b.inputDigest !== 'string' || b.provider !== 'syft-grype') throw new Error('Supply-chain report binding mismatch');
    const syftBytes = await readFile(safePath(context.repository.root, 'syft.cdx.json'));
    const grypeBytes = await readFile(safePath(context.repository.root, 'grype.json'));
    if (typeof b.syftSha256 === 'string' && sha256(syftBytes) !== b.syftSha256) throw new Error('Supply-chain Syft report hash mismatch');
    if (typeof b.grypeSha256 === 'string' && sha256(grypeBytes) !== b.grypeSha256) throw new Error('Supply-chain Grype report hash mismatch');
    const inventory = await reconcileRelationships(inventoryFromCycloneDx(syft), context, detectedAt);
    const matches = findingsFromGrype(grype, detectedAt);
    const findings = [...matches.map((item) => item.finding), ...inventory.unresolved.map((item) => unresolvedFinding(item, detectedAt))];
    const incompleteReasons: string[] = [];
    // Generic customer-supplied report imports preserve backward compatibility: unresolved package
    // identities fail closed, while absent relationship graphs remain explicitly visible evidence.
    // The shipped managed profile is stricter and fails when direct/transitive scope is unresolved.
    if (inventory.unresolved.length) incompleteReasons.push(`${inventory.unresolved.length} unresolved component(s)`);
    return {
      scanner: this.id,
      findings,
      evidence: [{
        schemaVersion: SCHEMA_VERSION,
        id: stableId('evidence', `${context.repository.commitSha}|supply-chain|${String(b.inputDigest)}`),
        type: 'supply-chain.scan', scanner: this.id, repository: context.repository.repository, commitSha: context.repository.commitSha, branch: context.repository.branch, generatedAt: detectedAt, findingIds: findings.map((finding) => finding.id),
        metadata: {
          provider: 'syft-grype-import', providerVersion: typeof b.providerVersion === 'string' ? b.providerVersion : 'unknown',
          componentCount: inventory.components.length,
          directComponentCount: inventory.relationshipCoverage.direct,
          transitiveComponentCount: inventory.relationshipCoverage.transitive,
          osComponentCount: inventory.relationshipCoverage.os,
          unknownRelationshipCount: inventory.relationshipCoverage.unknown,
          dependencyGraphAvailable: inventory.relationshipCoverage.graphAvailable,
          unresolvedComponentCount: inventory.unresolved.length, matchCount: matches.length,
          coverageComplete: incompleteReasons.length === 0, coverageLimitations: incompleteReasons.join('; '),
          inputDigest: String(b.inputDigest), syftReportSha256: sha256(syftBytes), grypeReportSha256: sha256(grypeBytes)
        }
      }],
      durationMs: Math.round(performance.now() - started),
      ...(incompleteReasons.length ? { status: 'failed' as const, error: `Dependency inventory coverage incomplete: ${incompleteReasons.join('; ')}` } : {})
    };
  }

  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now(); const detectedAt = context.now().toISOString();
    const runner = this.runner(context);
    return runner ? this.runManaged(context, started, detectedAt, runner) : this.runImported(context, started, detectedAt);
  }
}
