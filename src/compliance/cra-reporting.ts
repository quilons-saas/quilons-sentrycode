import type { AppliedFinding, ScanReport, Severity } from '../core/types.js';
import { stableId } from '../utils/hash.js';
import type { ComplianceIdentity } from './contracts.js';
import { COMPLIANCE_API_VERSION, SENTRYCODE_PLUGIN_ID } from './contracts.js';

export const CRA_REPORTING_CONTRACT_VERSION = '1.0.0' as const;

export interface CraEvidenceReference {
  apiVersion: typeof COMPLIANCE_API_VERSION;
  runId: string;
  evidenceIds: string[];
  resourcePath: string;
}

export interface CraFindingReport {
  schemaVersion: 1;
  contractVersion: typeof CRA_REPORTING_CONTRACT_VERSION;
  reportId: string;
  source: {
    pluginId: typeof SENTRYCODE_PLUGIN_ID;
    product: 'QUILONS SentryCode';
    version: string;
  };
  tenant: string;
  project: string;
  repository: string;
  finding: {
    id: string;
    type: string;
    scanner: string;
    ruleId: string;
    title: string;
    description: string;
    severity: Severity;
    status: 'active' | 'waived';
    waiverId?: string;
  };
  sourceRevision: {
    commitSha: string | null;
    branch: string | null;
    buildId?: string;
    jobId?: string;
    changeNumber?: string;
    patchsetNumber?: string;
    revision?: string;
  };
  evidenceReference: CraEvidenceReference;
  correlation: {
    runId: string;
  };
  timestamps: {
    detectedAt: string;
    scanCompletedAt: string;
    reportedAt: string;
  };
}

export interface CraFindingMateriality {
  severities: Severity[];
  findingTypes: string[];
}

function nonEmpty(value: string, label: string): string {
  if (!value.trim()) throw new Error(`${label} is required`);
  return value;
}

function normalizedTypes(values: string[]): Set<string> {
  return new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean));
}

/**
 * Applies the configured technical materiality filter only. This deliberately
 * performs no CRA regulatory mapping: severity and SentryCode finding type are
 * the existing technical facts used to decide whether a finding is a candidate
 * for proactive reporting.
 *
 * An empty findingTypes list means all finding types are eligible. An empty
 * severities list means no findings are eligible.
 */
export function isCraReportableFinding(appliedFinding: AppliedFinding, materiality: CraFindingMateriality): boolean {
  if (!materiality.severities.includes(appliedFinding.finding.severity)) return false;
  const types = normalizedTypes(materiality.findingTypes);
  return types.size === 0 || types.has(appliedFinding.finding.type.trim().toLowerCase());
}

/**
 * Selects CRA-reporting candidates from the already policy-applied findings in
 * a completed ScanReport. Waived findings remain technical facts and therefore
 * remain selectable; their governed waiver state is carried in the report.
 */
export function selectCraReportableFindings(report: ScanReport, materiality: CraFindingMateriality): AppliedFinding[] {
  return report.policy.findings.filter((item) => isCraReportableFinding(item, materiality));
}

/**
 * Builds the versioned technical-finding contract used by CRA reporting.
 * This function deliberately carries technical facts only; CRA regulatory
 * interpretation is outside SentryCode's responsibility.
 */
export function buildCraFindingReport(args: {
  identity: ComplianceIdentity;
  report: ScanReport;
  appliedFinding: AppliedFinding;
  productVersion: string;
  reportedAt?: string;
}): CraFindingReport {
  const tenant = nonEmpty(args.identity.tenant, 'tenant');
  const project = nonEmpty(args.identity.project, 'project');
  const repository = nonEmpty(args.report.repository.repository, 'repository');
  const productVersion = nonEmpty(args.productVersion, 'productVersion');
  const finding = args.appliedFinding.finding;
  nonEmpty(finding.id, 'finding.id');

  const evidenceIds = args.report.evidence
    .filter((item) => item.findingIds.includes(finding.id))
    .map((item) => item.id);
  if (evidenceIds.length === 0) throw new Error(`No authoritative evidence references finding ${finding.id}`);

  const ci = args.report.execution?.ci;
  const reportedAt = args.reportedAt ?? new Date().toISOString();
  const reportId = stableId('cra-report', `${tenant}|${project}|${repository}|${args.report.runId}|${finding.id}`);

  return {
    schemaVersion: 1,
    contractVersion: CRA_REPORTING_CONTRACT_VERSION,
    reportId,
    source: {
      pluginId: SENTRYCODE_PLUGIN_ID,
      product: 'QUILONS SentryCode',
      version: productVersion
    },
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
      resourcePath: `/v1/runs/${encodeURIComponent(args.report.runId)}/evidence`
    },
    correlation: { runId: args.report.runId },
    timestamps: {
      detectedAt: finding.detectedAt,
      scanCompletedAt: args.report.completedAt,
      reportedAt
    }
  };
}

/**
 * Converts only the selected material technical findings into CRA reporting
 * contracts. Evidence linkage remains fail-closed through buildCraFindingReport.
 */
export function buildCraFindingReports(args: {
  identity: ComplianceIdentity;
  report: ScanReport;
  productVersion: string;
  materiality: CraFindingMateriality;
  reportedAt?: string;
}): CraFindingReport[] {
  return selectCraReportableFindings(args.report, args.materiality).map((appliedFinding) => buildCraFindingReport({
    identity: args.identity,
    report: args.report,
    appliedFinding,
    productVersion: args.productVersion,
    ...(args.reportedAt ? { reportedAt: args.reportedAt } : {})
  }));
}
