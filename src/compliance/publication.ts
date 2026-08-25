import type { ComplianceIdentity, CompliancePublication, EvidenceEnvelope, StoredRunSummary } from './contracts.js';
import { COMPLIANCE_API_VERSION, SENTRYCODE_PLUGIN_ID } from './contracts.js';
import type { ScanReport } from '../core/types.js';
import { reportEvents } from './events.js';

export function buildPublication(identity: ComplianceIdentity, report: ScanReport, productVersion: string): CompliancePublication {
  const policyFingerprint = report.policy.effectivePolicy?.fingerprint;
  const summary: StoredRunSummary = {
    runId: report.runId,
    tenant: identity.tenant,
    project: identity.project,
    repository: report.repository.repository,
    commitSha: report.repository.commitSha,
    branch: report.repository.branch,
    decision: report.policy.decision,
    ...(policyFingerprint ? { policyFingerprint } : {}),
    startedAt: report.startedAt,
    completedAt: report.completedAt,
    evidenceCount: report.evidence.length,
    findingCount: report.policy.findings.length
  };
  const evidence: EvidenceEnvelope = {
    schemaVersion: 1,
    apiVersion: COMPLIANCE_API_VERSION,
    producer: { pluginId: SENTRYCODE_PLUGIN_ID, product: 'QUILONS SentryCode', version: productVersion },
    tenant: identity.tenant,
    project: identity.project,
    repository: report.repository.repository,
    runId: report.runId,
    decision: report.policy.decision,
    ...(policyFingerprint ? { policyFingerprint } : {}),
    generatedAt: report.completedAt,
    evidence: report.evidence
  };
  return { summary, evidence, report, events: reportEvents(identity, report) };
}
