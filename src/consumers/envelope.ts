import type { AppliedFinding, ScanReport } from '../core/types.js';
import { stableId } from '../utils/hash.js';
import type { ComplianceIdentity } from '../compliance/contracts.js';
import { COMPLIANCE_API_VERSION, SENTRYCODE_PLUGIN_ID } from '../compliance/contracts.js';
import { SENTRYCODE_CONSUMER_ENVELOPE_VERSION, type TechnicalFindingEnvelope } from './contracts.js';

function nonEmpty(value: string, label: string): string {
  if (!value.trim()) throw new Error(`${label} is required`);
  return value;
}

export function buildTechnicalFindingEnvelope(args: {
  identity: ComplianceIdentity;
  report: ScanReport;
  appliedFinding: AppliedFinding;
  productVersion: string;
  producedAt?: string;
}): TechnicalFindingEnvelope {
  const tenant = nonEmpty(args.identity.tenant, 'tenant');
  const project = nonEmpty(args.identity.project, 'project');
  const repository = nonEmpty(args.report.repository.repository, 'repository');
  const productVersion = nonEmpty(args.productVersion, 'productVersion');
  const finding = args.appliedFinding.finding;
  nonEmpty(finding.id, 'finding.id');

  const linkedEvidence = args.report.evidence.filter((item) => item.findingIds.includes(finding.id));
  const evidenceIds = linkedEvidence.map((item) => item.id);
  if (evidenceIds.length === 0) throw new Error(`No authoritative evidence references finding ${finding.id}`);
  const evidenceTypes = [...new Set(linkedEvidence.map((item) => item.type))].sort();

  const ci = args.report.execution?.ci;
  const producedAt = args.producedAt ?? new Date().toISOString();
  const messageId = stableId('sentrycode-finding', `${tenant}|${project}|${repository}|${args.report.runId}|${finding.id}`);

  return {
    schemaVersion: 1,
    contractVersion: SENTRYCODE_CONSUMER_ENVELOPE_VERSION,
    messageId,
    source: { pluginId: SENTRYCODE_PLUGIN_ID, product: 'QUILONS SentryCode', version: productVersion },
    tenant,
    project,
    repository,
    finding: {
      id: finding.id,
      type: finding.type,
      scanner: finding.scanner,
      ruleId: finding.ruleId,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      status: args.appliedFinding.waived ? 'waived' : 'active',
      ...(args.appliedFinding.waiverId ? { waiverId: args.appliedFinding.waiverId } : {})
    },
    sourceRevision: {
      commitSha: args.report.repository.commitSha,
      branch: args.report.repository.branch,
      ...(ci?.buildId ? { buildId: ci.buildId } : {}),
      ...(ci?.jobId ? { jobId: ci.jobId } : {}),
      ...(ci?.changeNumber ? { changeNumber: ci.changeNumber } : {}),
      ...(ci?.patchsetNumber ? { patchsetNumber: ci.patchsetNumber } : {}),
      ...(ci?.revision ? { revision: ci.revision } : {})
    },
    evidenceReference: {
      apiVersion: COMPLIANCE_API_VERSION,
      runId: args.report.runId,
      evidenceIds,
      evidenceTypes,
      resourcePath: `/v1/runs/${encodeURIComponent(args.report.runId)}/evidence`
    },
    correlation: { runId: args.report.runId },
    timestamps: { detectedAt: finding.detectedAt, scanCompletedAt: args.report.completedAt, producedAt }
  };
}
