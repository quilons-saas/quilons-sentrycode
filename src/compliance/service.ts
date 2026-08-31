import { access, constants } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ComplianceHealth, ComplianceIdentity, ComplianceReadiness, PluginManifest } from './contracts.js';
import { COMPLIANCE_API_VERSION, SENTRYCODE_PLUGIN_ID } from './contracts.js';
import { LocalComplianceStore } from './store.js';
import { loadPluginManifest } from './manifest.js';

export class SentryCodeComplianceService {
  readonly store: LocalComplianceStore;
  constructor(private readonly repositoryRoot: string, private readonly storeDirectory: string, integrity: { privateKeyFile?: string; publicKeyFile?: string } = {}) {
    this.store = new LocalComplianceStore(repositoryRoot, storeDirectory, integrity);
  }

  health(): ComplianceHealth { return { status: 'ok', pluginId: SENTRYCODE_PLUGIN_ID, apiVersion: COMPLIANCE_API_VERSION }; }
  async manifest(): Promise<PluginManifest> { return loadPluginManifest(this.repositoryRoot); }

  async readiness(): Promise<ComplianceReadiness> {
    const checks: ComplianceReadiness['checks'] = [];
    try { await access(resolve(this.repositoryRoot, 'package.json'), constants.R_OK); checks.push({ id: 'package', ok: true, detail: 'package.json readable' }); }
    catch { checks.push({ id: 'package', ok: false, detail: 'package.json not readable' }); }
    try { await access(this.repositoryRoot, constants.W_OK); checks.push({ id: 'store', ok: true, detail: 'repository root writable for configured local evidence store' }); }
    catch (error) { checks.push({ id: 'store', ok: false, detail: `local evidence store unavailable: ${(error as Error).message}` }); }
    return { ...this.health(), ready: checks.every((item) => item.ok), checks };
  }

  async listRuns(identity: ComplianceIdentity) { return this.store.listRuns(identity); }
  async getRun(identity: ComplianceIdentity, runId: string) { return this.store.getPublication(identity, runId); }
  async getFindings(identity: ComplianceIdentity, runId: string) {
    const run = await this.getRun(identity, runId);
    return run?.report.policy.findings ?? null;
  }
  async getEvidence(identity: ComplianceIdentity, runId: string) {
    const run = await this.getRun(identity, runId);
    return run?.evidence ?? null;
  }
  async getEvidenceById(identity: ComplianceIdentity, runId: string, evidenceId: string) {
    const envelope = await this.getEvidence(identity, runId);
    if (!envelope) return null;
    return envelope.evidence.find((item) => item.id === evidenceId) ?? null;
  }
  async getPolicyStatus(identity: ComplianceIdentity, runId: string) {
    const run = await this.getRun(identity, runId);
    if (!run) return null;
    return { decision: run.report.policy.decision, effectivePolicy: run.report.policy.effectivePolicy ?? null, reasons: run.report.policy.reasons };
  }
  async getWaiverStatus(identity: ComplianceIdentity, runId: string) {
    const run = await this.getRun(identity, runId);
    if (!run) return null;
    return {
      waivedCount: run.report.policy.waivedCount,
      findings: run.report.policy.findings.filter((item) => item.waived).map((item) => ({ findingId: item.finding.id, waiverId: item.waiverId ?? null })),
      audit: run.report.policy.audit.filter((item) => item.event === 'waiver.applied' || item.event === 'waiver.rejected')
    };
  }
}
