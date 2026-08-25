import { randomUUID } from 'node:crypto';
import type { EvidenceRecord, ReleaseDecision, ScanReport } from '../core/types.js';
import { SCHEMA_VERSION } from '../core/types.js';
import { stableId } from '../utils/hash.js';

export function buildReleaseDecision(report: ScanReport, now = new Date()): { decision: ReleaseDecision; evidence: EvidenceRecord } {
  const fingerprint = report.policy.effectivePolicy?.fingerprint ?? 'config-only';
  const decision: ReleaseDecision = {
    schemaVersion: SCHEMA_VERSION,
    releaseId: randomUUID(),
    evaluatedAt: now.toISOString(),
    repository: report.repository,
    decision: report.policy.decision,
    policyFingerprint: fingerprint,
    reasons: [...report.policy.reasons],
    evidenceIds: report.evidence.map((item) => item.id),
    scanRunId: report.runId
  };
  const evidence: EvidenceRecord = {
    schemaVersion: SCHEMA_VERSION,
    id: stableId('evidence', `${report.runId}|release.gate|${decision.evaluatedAt}`),
    type: 'release.gate',
    scanner: 'policy',
    repository: report.repository.repository,
    commitSha: report.repository.commitSha,
    branch: report.repository.branch,
    generatedAt: decision.evaluatedAt,
    findingIds: report.policy.findings.filter((item) => !item.waived).map((item) => item.finding.id),
    metadata: {
      decision: decision.decision,
      policyFingerprint: fingerprint,
      scanRunId: report.runId,
      evidenceCount: decision.evidenceIds.length
    }
  };
  return { decision, evidence };
}
