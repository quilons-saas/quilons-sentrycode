import type { Severity } from '../core/types.js';
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
  correlation: { runId: string };
  timestamps: {
    detectedAt: string;
    scanCompletedAt: string;
    reportedAt: string;
  };
}
