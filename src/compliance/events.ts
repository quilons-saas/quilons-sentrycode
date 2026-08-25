import { randomUUID } from 'node:crypto';
import type { ComplianceEvent, ComplianceIdentity } from './contracts.js';
import type { ScanReport } from '../core/types.js';

export function reportEvents(identity: ComplianceIdentity, report: ScanReport): ComplianceEvent[] {
  const base = {
    schemaVersion: 1 as const,
    source: 'quilons.sentrycode' as const,
    occurredAt: report.completedAt,
    tenant: identity.tenant,
    project: identity.project,
    repository: report.repository.repository
  };
  return [
    {
      ...base,
      id: randomUUID(),
      type: 'sentrycode.scan.completed',
      payload: {
        runId: report.runId,
        decision: report.policy.decision,
        commitSha: report.repository.commitSha,
        findingCount: report.policy.findings.length,
        evidenceCount: report.evidence.length
      }
    },
    {
      ...base,
      id: randomUUID(),
      type: 'sentrycode.evidence.available',
      payload: { runId: report.runId, evidenceTypes: [...new Set(report.evidence.map((item) => item.type))].sort() }
    }
  ];
}
