import type { AppliedFinding, ScanReport, Severity } from '../core/types.js';
import type { ComplianceIdentity } from './contracts.js';
import { buildTechnicalFindingEnvelope } from '../consumers/envelope.js';
import { CraConsumerAdapter } from '../consumers/cra-adapter.js';
import type { ConsumerConfig } from '../core/types.js';
export { CRA_REPORTING_CONTRACT_VERSION } from './cra-contracts.js';
export type { CraEvidenceReference, CraFindingReport } from './cra-contracts.js';
import type { CraFindingReport } from './cra-contracts.js';

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
  const envelope = buildTechnicalFindingEnvelope({
    identity: args.identity,
    report: args.report,
    appliedFinding: args.appliedFinding,
    productVersion: args.productVersion,
    ...(args.reportedAt ? { producedAt: args.reportedAt } : {})
  });
  const compatibilityConfig: ConsumerConfig = {
    consumerId: 'cra',
    adapter: 'cra',
    enabled: true,
    endpoint: '',
    tokenEnv: '',
    timeoutMs: 15000,
    maxAttempts: 5,
    retryDelayMs: 30000,
    scanProfile: { requiredScanners: [], evidenceTypes: [], severities: [], findingTypes: [] },
    context: {}
  };
  return new CraConsumerAdapter().mapFinding(envelope, compatibilityConfig);
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
