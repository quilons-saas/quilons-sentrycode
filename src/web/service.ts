import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ComplianceIdentity, CompliancePublication, StoredRunSummary } from '../compliance/contracts.js';
import { LocalComplianceStore } from '../compliance/store.js';
import type { SentryCodeConfig, Severity } from '../core/types.js';
import type { DashboardSummary, FindingView, RepositorySummary, RunDetailView, WebStatus } from './contracts.js';
import { WEB_API_VERSION } from './contracts.js';

const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export class SentryCodeWebService {
  private readonly store: LocalComplianceStore;
  constructor(private readonly repositoryRoot: string, private readonly config: SentryCodeConfig, private readonly identity: ComplianceIdentity | null) {
    this.store = new LocalComplianceStore(repositoryRoot, config.compliance.storeDirectory, {
      ...(config.integrity.evidenceSigningPrivateKeyFile ? { privateKeyFile: config.integrity.evidenceSigningPrivateKeyFile } : {}),
      ...(config.integrity.evidenceSigningPublicKeyFile ? { publicKeyFile: config.integrity.evidenceSigningPublicKeyFile } : {})
    });
  }

  private requireIdentity(): ComplianceIdentity {
    if (!this.identity) throw new Error('UI_SCOPE_NOT_CONFIGURED');
    return this.identity;
  }

  async status(): Promise<WebStatus> {
    const checks: WebStatus['checks'] = [];
    try { await readFile(resolve(this.repositoryRoot, 'package.json')); checks.push({ id: 'repository', ok: true, detail: 'repository package metadata readable' }); }
    catch { checks.push({ id: 'repository', ok: false, detail: 'repository package metadata not readable' }); }
    checks.push({ id: 'scope', ok: this.identity !== null, detail: this.identity ? `${this.identity.tenant} / ${this.identity.project}` : 'Set compliance.tenant/project or policy.context tenant/project to browse stored runs' });
    return {
      apiVersion: WEB_API_VERSION,
      product: 'QUILONS SentryCode',
      version: '0.1.0',
      health: 'ok',
      ready: checks.every((item) => item.ok),
      checks,
      scope: this.identity,
      repositoryRoot: this.repositoryRoot,
      ui: { mode: 'standalone', readOnly: true }
    };
  }

  async listRuns(): Promise<StoredRunSummary[]> { return this.store.listRuns(this.requireIdentity()); }
  async getPublication(runId: string): Promise<CompliancePublication | null> { return this.store.getPublication(this.requireIdentity(), runId); }

  async repositories(): Promise<RepositorySummary[]> {
    const runs = await this.listRuns();
    const byRepository = new Map<string, RepositorySummary>();
    for (const run of runs) {
      const current = byRepository.get(run.repository);
      if (!current) {
        byRepository.set(run.repository, { repository: run.repository, latestRunId: run.runId, latestDecision: run.decision, latestCommitSha: run.commitSha, latestBranch: run.branch, latestCompletedAt: run.completedAt, runCount: 1, findingCount: run.findingCount });
      } else {
        current.runCount += 1;
        current.findingCount += run.findingCount;
      }
    }
    return [...byRepository.values()].sort((a, b) => b.latestCompletedAt.localeCompare(a.latestCompletedAt));
  }

  async findings(): Promise<FindingView[]> {
    const runs = await this.listRuns();
    const result: FindingView[] = [];
    for (const run of runs) {
      const publication = await this.getPublication(run.runId);
      if (!publication) continue;
      for (const applied of publication.report.policy.findings) {
        result.push({
          runId: run.runId,
          repository: run.repository,
          commitSha: run.commitSha,
          branch: run.branch,
          decision: run.decision,
          finding: applied.finding,
          waived: applied.waived,
          ...(applied.waiverId ? { waiverId: applied.waiverId } : {})
        });
      }
    }
    return result.sort((a, b) => b.finding.detectedAt.localeCompare(a.finding.detectedAt));
  }

  async runDetail(runId: string): Promise<RunDetailView | null> {
    const publication = await this.getPublication(runId);
    if (!publication) return null;
    const summary = publication.summary;
    const findings: FindingView[] = publication.report.policy.findings.map((applied) => ({
      runId: summary.runId, repository: summary.repository, commitSha: summary.commitSha, branch: summary.branch, decision: summary.decision,
      finding: applied.finding, waived: applied.waived, ...(applied.waiverId ? { waiverId: applied.waiverId } : {})
    }));
    return {
      summary,
      report: {
        scanners: publication.report.scanners.map((scanner) => ({ scanner: scanner.scanner, status: scanner.status ?? 'success', durationMs: scanner.durationMs, findingCount: scanner.findings.length, ...(scanner.error ? { error: scanner.error } : {}) })),
        findings,
        reasons: publication.report.policy.reasons,
        waivedCount: publication.report.policy.waivedCount,
        effectivePolicy: publication.report.policy.effectivePolicy ?? null,
        execution: publication.report.execution ?? null
      },
      evidence: publication.evidence.evidence,
      integrity: { verified: true, signedVerificationRequired: Boolean(this.config.integrity.evidenceSigningPublicKeyFile) }
    };
  }

  async dashboard(): Promise<DashboardSummary> {
    const [runs, findings, repositories] = await Promise.all([this.listRuns(), this.findings(), this.repositories()]);
    const decisions = { PASS: 0, WARN: 0, FAIL: 0 };
    const severityCounts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    let waived = 0; let scannerFailures = 0; let evidence = 0;
    for (const run of runs) { decisions[run.decision] += 1; evidence += run.evidenceCount; }
    for (const item of findings) { severityCounts[item.finding.severity] += 1; if (item.waived) waived += 1; }
    for (const run of runs.slice(0, 50)) {
      const publication = await this.getPublication(run.runId);
      scannerFailures += publication?.report.scanners.filter((scanner) => (scanner.status ?? 'success') === 'failed').length ?? 0;
    }
    for (const severity of severities) severityCounts[severity] ??= 0;
    return { runs: runs.length, repositories: repositories.length, decisions, findings: severityCounts, waived, scannerFailures, evidence, recentRuns: runs.slice(0, 8) };
  }

  configSummary() {
    return {
      scanners: {
        secrets: { enabled: this.config.secrets.enabled, required: this.config.policy.requiredScanners.includes('secrets'), failureMode: this.config.policy.scannerFailureModes.secrets ?? 'ignore' },
        dependencies: { enabled: this.config.dependencies.enabled, required: this.config.policy.requiredScanners.includes('dependencies'), failureMode: this.config.policy.scannerFailureModes.dependencies ?? 'ignore' },
        sast: { enabled: this.config.sast.enabled, required: this.config.policy.requiredScanners.includes('sast'), failureMode: this.config.policy.scannerFailureModes.sast ?? 'ignore' },
        'git-assurance': { enabled: this.config.gitAssurance.enabled, required: this.config.policy.requiredScanners.includes('git-assurance'), failureMode: this.config.policy.scannerFailureModes['git-assurance'] ?? 'ignore' },
        provenance: { enabled: this.config.provenance.enabled, required: this.config.policy.requiredScanners.includes('provenance'), failureMode: this.config.policy.scannerFailureModes.provenance ?? 'ignore' },
        automotive: { enabled: this.config.automotive.enabled, required: this.config.policy.requiredScanners.includes('automotive'), failureMode: this.config.policy.scannerFailureModes.automotive ?? 'ignore' }
      },
      policy: { failOn: this.config.policy.failOn, warnOn: this.config.policy.warnOn, requiredScanners: this.config.policy.requiredScanners, directory: this.config.policy.directory },
      compliance: { enabled: this.config.compliance.enabled, scope: this.identity, storeDirectory: this.config.compliance.storeDirectory },
      integrity: { signedConfigRequired: this.config.integrity.requireSignedConfig, evidenceSigningEnabled: Boolean(this.config.integrity.evidenceSigningPrivateKeyFile), evidenceVerificationEnabled: Boolean(this.config.integrity.evidenceSigningPublicKeyFile) }
    };
  }
}
